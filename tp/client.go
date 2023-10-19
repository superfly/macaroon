package tp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/internal/merr"
)

type ClientOption func(*Client)

type Client struct {
	// Location identifier for the party that issued the first party macaroon.
	FirstPartyLocation string

	// HTTP client to use for requests to third parties. Third parties may try
	// to set cookies to expedite future discharge flows. This may be
	// facilitated by setting the http.Client's Jar field. With cookies enabled
	// it's important to use a different cookie jar and hence client when
	// fetching discharge tokens for multiple users.
	HTTP *http.Client

	// Function to call when when the third party needs to interact with the
	// end-user directly. The provided URL should be opened in the user's
	// browser if possible. Otherwise it should be displayed to the user and
	// they should be instructed to open it themselves. (Optional, but attempts
	// at user-interactive discharge flow will fail)
	UserURLCallback func(ctx context.Context, url string) error

	// A function determining how long to wait before making the next request
	// when polling the third party to see if a discharge is ready. This is
	// called the first time with a zero duration. (Optional)
	PollBackoffNext func(lastBO time.Duration) (nextBO time.Duration)
}

func (c *Client) FetchDischargeTokens(ctx context.Context, tokenHeader string) (string, error) {
	permTok, disToks, err := macaroon.ParsePermissionAndDischargeTokens(tokenHeader, c.FirstPartyLocation)
	if err != nil {
		return "", err
	}

	perm, err := macaroon.Decode(permTok)
	if err != nil {
		return "", err
	}

	tickets, err := perm.ThirdPartyTickets(disToks...)
	if err != nil {
		return "", err
	}

	var (
		wg          sync.WaitGroup
		m           sync.Mutex
		combinedErr error
	)

	for tpLoc, ticket := range tickets {
		wg.Add(1)
		go func(tpLoc string, ticket []byte) {
			defer wg.Done()

			dis, err := c.fetchDischargeToken(ctx, tpLoc, ticket)

			m.Lock()
			defer m.Unlock()

			if err != nil {
				combinedErr = merr.Append(combinedErr, err)
			} else {
				tokenHeader = tokenHeader + "," + dis
			}
		}(tpLoc, ticket)
	}

	wg.Wait()

	return tokenHeader, combinedErr
}

func (c *Client) fetchDischargeToken(ctx context.Context, thirdPartyLocation string, ticket []byte) (string, error) {
	jresp, err := c.doInitRequest(ctx, thirdPartyLocation, ticket)

	switch {
	case err != nil:
		return "", err
	case jresp.Discharge != "":
		return jresp.Discharge, nil
	case jresp.PollURL != "":
		return c.doPoll(ctx, jresp.PollURL)
	case jresp.UserInteractive != nil:
		return c.doUserInteractive(ctx, jresp.UserInteractive)
	default:
		return "", errors.New("bad discharge response")
	}
}

func (c *Client) doInitRequest(ctx context.Context, thirdPartyLocation string, ticket []byte) (*jsonResponse, error) {
	jreq := &jsonInitRequest{
		Ticket: ticket,
	}

	breq, err := json.Marshal(jreq)
	if err != nil {
		return nil, err
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, initURL(thirdPartyLocation), bytes.NewReader(breq))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")

	hresp, err := c.http().Do(hreq)
	if err != nil {
		return nil, err
	}

	var jresp jsonResponse
	if err := json.NewDecoder(hresp.Body).Decode(&jresp); err != nil {
		return nil, fmt.Errorf("bad response (%d): %w", hresp.StatusCode, err)
	}

	if jresp.Error != "" {
		return nil, &Error{hresp.StatusCode, jresp.Error}
	}

	return &jresp, nil
}

func (c *Client) doPoll(ctx context.Context, pollURL string) (string, error) {
	if pollURL == "" {
		return "", errors.New("bad discharge response")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return "", err
	}

	var (
		bo    time.Duration
		jresp jsonResponse
	)

pollLoop:
	for {
		hresp, err := c.http().Do(req)
		if err != nil {
			return "", err
		}

		if hresp.StatusCode == http.StatusAccepted {
			bo = c.nextBO(bo)

			select {
			case <-time.After(bo):
				continue pollLoop
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		if err := json.NewDecoder(hresp.Body).Decode(&jresp); err != nil {
			return "", fmt.Errorf("bad response (%d): %w", hresp.StatusCode, err)
		}
		if jresp.Error != "" {
			return "", &Error{hresp.StatusCode, jresp.Error}
		}
		if jresp.Discharge == "" {
			return "", fmt.Errorf("bad response (%d): missing discharge", hresp.StatusCode)
		}

		return jresp.Discharge, nil
	}
}

func (c *Client) doUserInteractive(ctx context.Context, ui *jsonUserInteractive) (string, error) {
	if ui.PollURL == "" || ui.UserURL == "" {
		return "", errors.New("bad discharge response")
	}
	if c.UserURLCallback == nil {
		return "", errors.New("missing user-url callback")
	}

	if err := c.openUserInteractiveURL(ctx, ui.UserURL); err != nil {
		return "", err
	}

	return c.doPoll(ctx, ui.PollURL)
}

func (c *Client) nextBO(lastBO time.Duration) time.Duration {
	if c.PollBackoffNext != nil {
		return c.PollBackoffNext(lastBO)
	}
	if lastBO == 0 {
		return time.Second
	}
	return 2 * lastBO
}

func (c *Client) openUserInteractiveURL(ctx context.Context, url string) error {
	if c.UserURLCallback != nil {
		return c.UserURLCallback(ctx, url)
	}

	return errors.New("client not configured for opening URLs")
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func initURL(location string) string {
	if strings.HasSuffix(location, "/") {
		return location + InitPath[1:]
	}
	return location + InitPath
}

type Error struct {
	StatusCode int
	Msg        string
}

func (e Error) Error() string {
	return fmt.Sprintf("tp error (%d): %s", e.StatusCode, e.Msg)
}
