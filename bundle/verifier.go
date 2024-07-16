package bundle

import (
	"context"
	"fmt"

	"github.com/superfly/macaroon"
)

// VerificationResult is a VerifiedMacaroon or InvalidMacaroon.
type VerificationResult interface {
	Macaroon
	isVerificationResult()
}

// Verifier verifies macaroons.
type Verifier interface {
	// Verify does the work of verifying a map of macaroons. It takes a mapping
	// of permission tokens to their potential discharge tokens. It returns a
	// mapping from permission to verification results (either VerifiedMacaroon
	// or InvalidMacaroon).
	Verify(ctx context.Context, dischargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult
}

// KeyResolver is a helper for generating a Verifier for use by macaroon
// authorities. It is responsible for looking up the appropriate key to use for
// the given nonce's KID.
type KeyResolver func(context.Context, macaroon.Nonce) (macaroon.SigningKey, map[string][]macaroon.EncryptionKey, error)

// WithKey returns a KeyResolver for authorities with a single key.
func WithKey(kid []byte, key macaroon.SigningKey, trustedTPs map[string][]macaroon.EncryptionKey) KeyResolver {
	return WithKeys(map[string]macaroon.SigningKey{string(kid): key}, trustedTPs)
}

// WithKeys returns a KeyResolver for authorities with multiple keys.
func WithKeys(keyByKID map[string]macaroon.SigningKey, trustedTPs map[string][]macaroon.EncryptionKey) KeyResolver {
	return func(_ context.Context, nonce macaroon.Nonce) (macaroon.SigningKey, map[string][]macaroon.EncryptionKey, error) {
		key, ok := keyByKID[string(nonce.KID)]
		if !ok {
			return nil, nil, fmt.Errorf("unknown KID %x", nonce.KID)
		}

		return key, trustedTPs, nil
	}

}

func (kr KeyResolver) Verify(ctx context.Context, dissByPerm map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
	ret := make(map[Macaroon]VerificationResult, len(dissByPerm))

	for perm, diss := range dissByPerm {
		key, trustedTPs, err := kr(ctx, perm.Nonce())
		if err != nil {
			ret[perm] = &InvalidMacaroon{perm.Unverified(), err}
			continue
		}

		disMacs := make([]*macaroon.Macaroon, 0, len(diss))
		for _, d := range diss {
			disMacs = append(disMacs, d.UnsafeMacaroon())
		}

		if cavs, err := perm.UnsafeMacaroon().VerifyParsed(key, disMacs, trustedTPs); err != nil {
			ret[perm] = &InvalidMacaroon{perm.Unverified(), err}
		} else {
			ret[perm] = &VerifiedMacaroon{perm.Unverified(), cavs}
		}
	}

	return ret
}
