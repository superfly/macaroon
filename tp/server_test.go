package tp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		case path == PollPath:
			tp.HandlePollRequest(w, r)
		case strings.HasPrefix(path, "/user/"):
			tp.UserRequestMiddleware(handleUser).ServeHTTP(w, r)
		default:
			panic("huh?")
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

		ticket, fp := genFP(t, tp, myCaveat("fp-cav"))
		reqb, err := json.Marshal(&jsonInitRequest{Ticket: ticket})
		assert.NoError(t, err)

		res, err := s.Client().Post(s.URL+InitPath, "application/json", bytes.NewReader(reqb))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		var jres jsonInitResponse
		assert.NoError(t, json.NewDecoder(res.Body).Decode(&jres))

		cavs := checkFP(t, fp, jres.Discharge)
		assert.Equal(t, []string{"fp-cav", "dis-cav"}, cavs)
	})
}

var (
	fpLoc = "https://first-party"
	fpKey = macaroon.NewSigningKey()
	fpKID = []byte{1, 2, 3}
)

func genFP(tb testing.TB, tp *TP, caveats ...macaroon.Caveat) ([]byte, string) {
	tb.Helper()

	m, err := macaroon.New(fpKID, fpLoc, fpKey)
	assert.NoError(tb, err)

	assert.NoError(tb, m.Add(caveats...))
	assert.NoError(tb, m.Add3P(tp.Key, tp.Location, caveats...))

	tok, err := m.String()
	assert.NoError(tb, err)

	ticket, err := m.ThirdPartyTicket(tp.Location)
	assert.NoError(tb, err)

	return ticket, tok
}

func checkFP(tb testing.TB, fp string, dis string) []string {
	tb.Helper()

	fpb, err := macaroon.Parse(fp)
	assert.NoError(tb, err)

	disb, err := macaroon.Parse(dis)
	assert.NoError(tb, err)

	m, err := macaroon.Decode(fpb[0])
	assert.NoError(tb, err)

	cs, err := m.Verify(fpKey, disb, nil)
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
