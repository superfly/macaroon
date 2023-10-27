package macaroon

import (
	"fmt"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

// wireTicket is the magic blob callers pass to 3rd-party services to obtain discharge
// Macaroons for 3P claims (the Macaroon Caveat itself has a Location field that
// tells callers where to send these).
//
// This is the plaintext of a blob that is encrypted in the actual Macaroon.
//
// Just remember: users exchange tickets for discharge Macaroons
type wireTicket struct {
	DischargeKey []byte
	Caveats      CaveatSet
}

// Checks the macaroon for a third party caveat for the specified location.
// Returns the caveat's encrypted ticket, if found.
func ThirdPartyTicket(encodedMacaroon []byte, thirdPartyLocation string) ([]byte, error) {
	m, err := Decode(encodedMacaroon)
	if err != nil {
		return nil, err
	}

	return m.ThirdPartyTicket(thirdPartyLocation)
}

// Decyrpts the ticket from the 3p caveat and prepares a discharge token. Returned
// caveats, if any, must be validated before issuing the discharge token to the
// user.
func DischargeTicket(ka EncryptionKey, location string, ticket []byte) ([]Caveat, *Macaroon, error) {
	return dischargeTicket(ka, location, ticket, true)
}

// discharge macaroons will be proofs moving forward, but we need to be able to test the old non-proof dms too
func dischargeTicket(ka EncryptionKey, location string, ticket []byte, issueProof bool) ([]Caveat, *Macaroon, error) {
	tRaw, err := unseal(ka, ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("recover for discharge: ticket decrypt: %w", err)
	}

	tWire := &wireTicket{}
	if err = msgpack.Unmarshal(tRaw, tWire); err != nil {
		return nil, nil, fmt.Errorf("recover for discharge: ticket decode: %w", err)
	}

	dm, err := newMacaroon(ticket, location, tWire.DischargeKey, issueProof)
	if err != nil {
		return nil, nil, err
	}

	return tWire.Caveats.Caveats, dm, nil
}
