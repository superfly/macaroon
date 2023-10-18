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

type Client struct {
	FirstPartyLocation string
	UserURLCallback    func(url string) error
	PollBackoffInitial time.Duration
	PollBackoffNext    func(time.Duration) time.Duration
}

func (c *Client) FetchDischargeTokens(ctx context.Context, tokenHeader string, httpClient *http.Client) (string, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

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

	discharges := make([]*ClientDischarge, 0, len(tickets))
	wg := new(sync.WaitGroup)

	for tpLoc, ticket := range tickets {
		discharge := &ClientDischarge{
			Client:             c,
			HTTP:               httpClient,
			ThirdPartyLocation: tpLoc,
			Ticket:             ticket,
			Ctx:                ctx,
		}
		discharges = append(discharges, discharge)

		wg.Add(1)
		go func() {
			defer wg.Done()
			discharge.Run()
		}()
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return "", err
	}

	err = nil
	for _, discharge := range discharges {
		switch {
		case discharge.Discharge != "":
			tokenHeader = tokenHeader + "," + discharge.Discharge
		case discharge.Error != nil:
			err = merr.Append(err, discharge.Error)
		default:
			err = merr.Append(err, errors.New("shouldn't happen"))
		}
	}

	return tokenHeader, err
}

type ClientDischarge struct {
	Client             *Client
	HTTP               *http.Client
	ThirdPartyLocation string
	Ticket             []byte
	Ctx                context.Context

	// results
	Discharge string
	Error     error
}

func (cd *ClientDischarge) Run() {
	jresp, err := cd.DoInitRequest()

	switch {
	case err != nil:
		cd.Error = err
	case jresp.Discharge != "":
		cd.Discharge = jresp.Discharge
	case jresp.PollURL != "":
		cd.Discharge, cd.Error = cd.DoPoll(jresp.PollURL)
	case jresp.UserInteractive != nil:
		cd.Discharge, cd.Error = cd.DoUserInteractive(jresp.UserInteractive)
	default:
		cd.Error = errors.New("bad discharge response")
	}
}

func (cd *ClientDischarge) DoInitRequest() (*jsonResponse, error) {
	jreq := &jsonInitRequest{
		Ticket: cd.Ticket,
	}

	breq, err := json.Marshal(jreq)
	if err != nil {
		return nil, err
	}

	hreq, err := http.NewRequestWithContext(cd.Ctx, http.MethodPost, cd.url(""), bytes.NewReader(breq))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")

	hresp, err := cd.HTTP.Do(hreq)
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

func (cd *ClientDischarge) DoPoll(pollURL string) (string, error) {
	if pollURL == "" {
		return "", errors.New("bad discharge response")
	}

	req, err := http.NewRequestWithContext(cd.Ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return "", err
	}

	var (
		bo    = cd.Client.PollBackoffInitial
		jresp jsonResponse
	)

pollLoop:
	for {
		hresp, err := cd.HTTP.Do(req)
		if err != nil {
			return "", err
		}

		if hresp.StatusCode == http.StatusAccepted {
			select {
			case <-time.After(bo):
				bo = cd.Client.PollBackoffNext(bo)
				continue pollLoop
			case <-cd.Ctx.Done():
				return "", cd.Ctx.Err()
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

func (cd *ClientDischarge) DoUserInteractive(ui *jsonUserInteractive) (string, error) {
	if ui.PollURL == "" || ui.UserURL == "" {
		return "", errors.New("bad discharge response")
	}

	if err := cd.Client.UserURLCallback(ui.UserURL); err != nil {
		return "", err
	}

	return cd.DoPoll(ui.PollURL)
}

func (cd *ClientDischarge) url(path string) string {
	if strings.HasSuffix(cd.ThirdPartyLocation, "/") {
		return cd.ThirdPartyLocation + InitPath[1:] + path
	}
	return cd.ThirdPartyLocation + InitPath + path
}

type Error struct {
	StatusCode int
	Msg        string
}

func (e Error) Error() string {
	return fmt.Sprintf("tp error (%d): %s", e.StatusCode, e.Msg)
}
