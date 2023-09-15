package macaroon

import (
	"fmt"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

// wireCID is the magic blob callers pass to 3rd-party services to obtain discharge
// Macaroons for 3P claims (the Macaroon Caveat itself has a Location field that
// tells callers where to send these).
//
// This is the plaintext of a blob that is encrypted in the actual Macaroon.
//
// Just remember: users exchange CIDs for discharge Macaroons
type wireCID struct {
	RN      []byte
	Caveats CaveatSet
}

// Checks the macaroon for a third party caveat for the specified location.
// Returns the caveat's encrypted CID, if found.
func ThirdPartyCID(encodedMacaroon []byte, thirdPartyLocation string) ([]byte, error) {
	m, err := Decode(encodedMacaroon)
	if err != nil {
		return nil, err
	}

	return m.ThirdPartyCID(thirdPartyLocation)
}

// Decyrpts the CID from the 3p caveat and prepares a discharge token. Returned
// caveats, if any, must be validated before issuing the discharge token to the
// user.
func DischargeCID(ka EncryptionKey, location string, cid []byte) ([]Caveat, *Macaroon, error) {
	return dischargeCID(ka, location, cid, true)
}

// discharge macaroons will be proofs moving forward, but we need to be able to test the old non-proof dms too
func dischargeCID(ka EncryptionKey, location string, cid []byte, issueProof bool) ([]Caveat, *Macaroon, error) {
	cidr, err := unseal(ka, cid)
	if err != nil {
		return nil, nil, fmt.Errorf("recover for discharge: CID decrypt: %w", err)
	}

	tcid := &wireCID{}
	if err = msgpack.Unmarshal(cidr, tcid); err != nil {
		return nil, nil, fmt.Errorf("recover for discharge: CID decode: %w", err)
	}

	dm, err := newMacaroon(cid, location, tcid.RN, issueProof)
	if err != nil {
		return nil, nil, err
	}

	return tcid.Caveats.Caveats, dm, nil
}
