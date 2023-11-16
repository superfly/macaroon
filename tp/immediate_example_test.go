package tp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
)

type immediateSever struct {
	tp *TP
	*http.ServeMux
}

func newImmediateServer(tp *TP) *immediateSever {
	is := &immediateSever{
		tp:       tp,
		ServeMux: http.NewServeMux(),
	}

	is.Handle(InitPath, tp.InitRequestMiddleware(http.HandlerFunc(is.handleInitRequest)))

	return is
}

func (is *immediateSever) handleInitRequest(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer trustno1" {
		is.tp.RespondError(w, r, http.StatusUnauthorized, "bad client authentication")
		return
	}

	// discharge token will be valid for one minute
	caveat := &macaroon.ValidityWindow{
		NotBefore: time.Now().Unix(),
		NotAfter:  time.Now().Add(time.Minute).Unix(),
	}

	is.tp.RespondDischarge(w, r, caveat)
}

var immediateServerKey = macaroon.NewEncryptionKey()

func ExampleTP_RespondDischarge() {
	tp := &TP{
		Key: immediateServerKey,
		Log: logrus.StandardLogger(),
	}

	is := newImmediateServer(tp)

	hs := httptest.NewServer(is)
	defer hs.Close()

	tp.Location = hs.URL

	// simulate user getting/having a 1st party macaroon with a 3rd party caveat
	firstPartyMacaroon, err := getFirstPartyMacaroonWithThirdPartyCaveat(
		tp.Location,
		immediateServerKey,
	)
	if err != nil {
		panic(err)
	}

	_, err = validateFirstPartyMacaroon(firstPartyMacaroon)
	fmt.Printf("validation error without 3p discharge token: %v\n", err)

	client := NewClient(firstPartyLocation,
		WithBearerAuthentication(tp.Location, "trustno1"),
	)

	firstPartyMacaroon, err = client.FetchDischargeTokens(context.Background(), firstPartyMacaroon)
	if err != nil {
		panic(err)
	}

	_, err = validateFirstPartyMacaroon(firstPartyMacaroon)
	fmt.Printf("validation error with 3p discharge token: %v\n", err)

	// Output:
	// validation error without 3p discharge token: no matching discharge token
	// validation error with 3p discharge token: <nil>
}
