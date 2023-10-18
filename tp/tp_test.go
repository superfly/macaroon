package tp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
)

func TestServer(t *testing.T) {
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
		c := &Client{FirstPartyLocation: fpLoc}
		hdr, err = c.FetchDischargeTokens(context.Background(), hdr, nil)
		assert.NoError(t, err)
		cavs := checkFP(t, hdr)
		assert.Equal(t, []string{"fp-cav", "dis-cav"}, cavs)
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

		c := &Client{
			FirstPartyLocation: fpLoc,
			PollBackoffInitial: 10 * time.Millisecond,
			PollBackoffNext:    func(d time.Duration) time.Duration { return 10 * time.Second },
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		go func() {
			select {
			case <-pollSecretSet:
				select {
				case <-time.After(5 * time.Millisecond):
					assert.NoError(t, tp.DischargePoll(pollSecret, myCaveat("dis-cav")))
				case <-ctx.Done():
					panic("oh no")
				}
			case <-ctx.Done():
				panic("oh no")
			}
		}()

		hdr, err = c.FetchDischargeTokens(ctx, hdr, nil)
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

		c := &Client{
			FirstPartyLocation: fpLoc,
			PollBackoffInitial: 10 * time.Millisecond,
			PollBackoffNext:    func(d time.Duration) time.Duration { return 10 * time.Second },
			UserURLCallback: func(url string) error {
				time.Sleep(10 * time.Millisecond)
				assert.NoError(t, tp.DischargeUserInteractive(userSecret, myCaveat("dis-cav")))
				return nil
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		hdr, err = c.FetchDischargeTokens(ctx, hdr, nil)
		assert.NoError(t, err)
		cavs := checkFP(t, hdr)
		assert.Equal(t, []string{"fp-cav", "dis-cav"}, cavs)
	})
}

var (
	fpLoc = "https://first-party"
	fpKey = macaroon.NewSigningKey()
	fpKID = []byte{1, 2, 3}
)

func genFP(tb testing.TB, tp *TP, caveats ...macaroon.Caveat) string {
	tb.Helper()

	m, err := macaroon.New(fpKID, fpLoc, fpKey)
	assert.NoError(tb, err)

	assert.NoError(tb, m.Add(caveats...))
	assert.NoError(tb, m.Add3P(tp.Key, tp.Location, caveats...))

	tok, err := m.Encode()
	assert.NoError(tb, err)

	return macaroon.ToAuthorizationHeader(tok)
}

func checkFP(tb testing.TB, hdr string) []string {
	tb.Helper()

	fpb, dissb, err := macaroon.ParsePermissionAndDischargeTokens(hdr, fpLoc)
	assert.NoError(tb, err)

	m, err := macaroon.Decode(fpb)
	assert.NoError(tb, err)

	cs, err := m.Verify(fpKey, dissb, nil)
	assert.NoError(tb, err)

	cavs := macaroon.GetCaveats[*myCaveat](cs)
	ret := make([]string, len(cavs))
	for i := range cavs {
		ret[i] = string(*cavs[i])
	}

	return ret
}

type myCaveat string

func init() { macaroon.RegisterCaveatType(new(myCaveat)) }

func (c myCaveat) CaveatType() macaroon.CaveatType   { return macaroon.CavMinUserDefined }
func (c myCaveat) Name() string                      { return "myCaveat" }
func (c myCaveat) Prohibits(f macaroon.Access) error { return nil }
