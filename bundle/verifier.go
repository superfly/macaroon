package bundle

import (
	"bytes"
	"fmt"

	"github.com/superfly/macaroon"
)

type VerificationResult interface {
	Macaroon
	isVerificationResult()
}

// Verifier verifies macaroons.
type Verifier interface {
	// Verify does the work of verifying a map of macaroons. It takes a mapping
	// of permission tokens to their potential discharge tokens. It returns a
	// mapping from permission to verification results (either VerifiedMacaroon
	// or InvalidMacaroon)
	Verify(disschargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult
}

// AuthorityVerifier is a Verifier for use by macaroon authorities. It is
// responsible for looking up the appropriate key to use for the given nonce's
// KID.
type AuthorityVerifier func(macaroon.Nonce) (macaroon.SigningKey, map[string][]macaroon.EncryptionKey, error)

// WithKey returns a KeyResolver for authorities with a single key.
func WithKey(kid []byte, key macaroon.SigningKey, trustedTPs map[string][]macaroon.EncryptionKey) AuthorityVerifier {
	return func(nonce macaroon.Nonce) (macaroon.SigningKey, map[string][]macaroon.EncryptionKey, error) {
		if bytes.Equal(nonce.KID, kid) {
			return key, trustedTPs, nil
		}

		return nil, nil, fmt.Errorf("unknown KID %x", nonce.KID)
	}
}

// Verify implements Verifier.
func (av AuthorityVerifier) Verify(dissByPerm map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
	ret := make(map[Macaroon]VerificationResult, len(dissByPerm))

	for perm, diss := range dissByPerm {
		var (
			permMac  = perm.getUnsafeMacaroon()
			dissMacs = make([]*macaroon.Macaroon, 0, len(diss))
		)

		for _, d := range diss {
			dissMacs = append(dissMacs, d.getUnsafeMacaroon())
		}

		key, trustedTPs, err := av(permMac.Nonce)
		if err != nil {
			ret[perm] = InvalidMacaroon(perm, err)
			continue
		}

		if cavs, err := permMac.VerifyParsed(key, dissMacs, trustedTPs); err != nil {
			ret[perm] = InvalidMacaroon(perm, err)
		} else {
			ret[perm] = VerifiedMacaroon(perm, cavs)
		}
	}

	return ret
}
