package tp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
)

func TestTP(t *testing.T) {
	var (
		tp                     *TP
		handleInit, handleUser http.Handler
	)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()

		switch {
		case path == InitPath:
			tp.InitRequestMiddleware(handleInit).ServeHTTP(w, r)
		case strings.HasPrefix(path, PollPathPrefix):
			tp.HandlePollRequest(w, r)
		case strings.HasPrefix(path, "/user/"):
			tp.UserRequestMiddleware(handleUser).ServeHTTP(w, r)
		default:
			panic(r.URL.EscapedPath())
		}
	}))
	t.Cleanup(s.Close)

	ms, err := NewMemoryStore(PrefixMunger("/user/"), 100)
	assert.NoError(t, err)

	tp = &TP{
		Location: s.URL,
		Key:      macaroon.NewEncryptionKey(),
		Store:    ms,
		Log:      logrus.StandardLogger(),
	}

	t.Run("immediate response", func(t *testing.T) {
		handleInit = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := CaveatsFromRequest(r)
			assert.NoError(t, err)

			tp.RespondDischarge(w, r, myCaveat("dis-cav"))
		})

		hdr := genFP(t, tp, myCaveat("fp-cav"))
		c := NewClient(firstPartyLocation)
		hdr, err = c.FetchDischargeTokens(context.Background(), hdr)
		assert.NoError(t, err)
		cavs := checkFP(t, hdr)
		assert.Equal(t, []string{"fp-cav", "dis-cav"}, cavs)
	})

	t.Run("WithBearerAuthentication", func(t *testing.T) {
		t.Run("sends token to correct host", func(t *testing.T) {
			handleInit = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer my-token" {
					tp.RespondError(w, r, http.StatusUnauthorized, "bad client authentication")
					return
				}
				_, err := CaveatsFromRequest(r)
				assert.NoError(t, err)

				tp.RespondDischarge(w, r)
			})

			u, err := url.Parse(tp.Location)
			assert.NoError(t, err)

			hdr := genFP(t, tp)
			c := NewClient(firstPartyLocation,
				WithBearerAuthentication(u.Hostname(), "my-token"),
			)
			hdr, err = c.FetchDischargeTokens(context.Background(), hdr)
			assert.NoError(t, err)
			checkFP(t, hdr)
		})

		t.Run("doesn't send token to wrong host", func(t *testing.T) {
			handleInit = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					tp.RespondError(w, r, http.StatusUnauthorized, "bad client authentication")
					return
				}
				_, err := CaveatsFromRequest(r)
				assert.NoError(t, err)

				tp.RespondDischarge(w, r)
			})

			hdr := genFP(t, tp)
			c := NewClient(firstPartyLocation,
				WithBearerAuthentication("wrong.com", "my-token"),
			)
			hdr, err = c.FetchDischargeTokens(context.Background(), hdr)
			assert.NoError(t, err)
			checkFP(t, hdr)
		})
	})

	t.Run("poll response", func(t *testing.T) {
		pollSecret := ""
		pollSecretSet := make(chan struct{})

		handleInit = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := CaveatsFromRequest(r)
			assert.NoError(t, err)

			pollSecret = tp.RespondPoll(w, r)
			close(pollSecretSet)
		})

		hdr := genFP(t, tp, myCaveat("fp-cav"))

		c := NewClient(firstPartyLocation,
			WithPollingBackoff(func(last time.Duration) time.Duration {
				if last == 0 {
					return 10 * time.Millisecond
				}
				return 10 * time.Second
			}),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		go func() {
			select {
			case <-pollSecretSet:
				select {
				case <-time.After(5 * time.Millisecond):
					assert.NoError(t, tp.DischargePoll(context.Background(), pollSecret, myCaveat("dis-cav")))
				case <-ctx.Done():
					panic("oh no")
				}
			case <-ctx.Done():
				panic("oh no")
			}
		}()

		hdr, err = c.FetchDischargeTokens(ctx, hdr)
		assert.NoError(t, err)
		cavs := checkFP(t, hdr)
		assert.Equal(t, []string{"fp-cav", "dis-cav"}, cavs)
	})

	t.Run("user interactive response", func(t *testing.T) {
		userSecret := ""

		handleInit = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := CaveatsFromRequest(r)
			assert.NoError(t, err)

			userSecret = tp.RespondUserInteractive(w, r)
		})

		hdr := genFP(t, tp, myCaveat("fp-cav"))

		c := NewClient(firstPartyLocation,
			WithPollingBackoff(func(last time.Duration) time.Duration {
				if last == 0 {
					return 10 * time.Millisecond
				}
				return 10 * time.Second
			}),
			WithUserURLCallback(func(_ context.Context, url string) error {
				time.Sleep(10 * time.Millisecond)
				assert.NoError(t, tp.DischargeUserInteractive(context.Background(), userSecret, myCaveat("dis-cav")))
				return nil
			}),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		hdr, err = c.FetchDischargeTokens(ctx, hdr)
		assert.NoError(t, err)
		cavs := checkFP(t, hdr)
		assert.Equal(t, []string{"fp-cav", "dis-cav"}, cavs)
	})
}

var (
	firstPartyLocation = "https://first-party"
	fpKey              = macaroon.NewSigningKey()
	fpKID              = []byte{1, 2, 3}
)

func getFirstPartyMacaroonWithThirdPartyCaveat(thirdPartyLocation string, thirdPartyKey macaroon.EncryptionKey, otherCaveats ...macaroon.Caveat) (string, error) {
	m, err := macaroon.New(fpKID, firstPartyLocation, fpKey)
	if err != nil {
		return "", err
	}

	if err := m.Add(otherCaveats...); err != nil {
		return "", err
	}

	if err := m.Add3P(thirdPartyKey, thirdPartyLocation); err != nil {
		return "", err
	}

	tok, err := m.Encode()
	if err != nil {
		return "", err
	}

	return macaroon.ToAuthorizationHeader(tok), nil
}

func genFP(tb testing.TB, tp *TP, caveats ...macaroon.Caveat) string {
	tb.Helper()

	hdr, err := getFirstPartyMacaroonWithThirdPartyCaveat(tp.Location, tp.Key, caveats...)
	assert.NoError(tb, err)

	return hdr
}

func validateFirstPartyMacaroon(tokenHeader string) (*macaroon.CaveatSet, error) {
	fpb, dissb, err := macaroon.ParsePermissionAndDischargeTokens(tokenHeader, firstPartyLocation)
	if err != nil {
		return nil, err
	}

	m, err := macaroon.Decode(fpb)
	if err != nil {
		return nil, err
	}

	cs, err := m.Verify(fpKey, dissb, nil)
	if err != nil {
		return nil, err
	}

	return cs, nil
}

func checkFP(tb testing.TB, hdr string) []string {
	tb.Helper()

	cs, err := validateFirstPartyMacaroon(hdr)
	assert.NoError(tb, err)

	cavs := macaroon.GetCaveats[*myCaveat](cs)
	ret := make([]string, len(cavs))
	for i := range cavs {
		ret[i] = string(*cavs[i])
	}

	return ret
}

func basicAuthClient(username, password string) *http.Client {
	return &http.Client{
		Transport: &basicAuthTransport{
			t:        http.DefaultTransport.(*http.Transport).Clone(),
			username: username,
			password: password,
		},
	}
}

type basicAuthTransport struct {
	t                  http.RoundTripper
	username, password string
}

func (bat *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(bat.username, bat.password)
	return bat.t.RoundTrip(req)
}

type myCaveat string

func init() { macaroon.RegisterCaveatType(new(myCaveat)) }

func (c myCaveat) CaveatType() macaroon.CaveatType   { return macaroon.CavMinUserDefined }
func (c myCaveat) Name() string                      { return "myCaveat" }
func (c myCaveat) Prohibits(f macaroon.Access) error { return nil }
