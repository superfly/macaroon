package bundle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"slices"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/superfly/macaroon"
)

// VerificationResult is a VerifiedMacaroon or FailedMacaroon.
type VerificationResult interface {
	Macaroon
	isVerificationResult()
}

// Verifier verifies macaroons.
type Verifier interface {
	// Verify does the work of verifying a map of macaroons. It takes a mapping
	// of permission tokens to their potential discharge tokens. It returns a
	// mapping from permission to verification results (either VerifiedMacaroon
	// or FailedMacaroon).
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
	return VerifierFunc(kr.VerifyOne).Verify(ctx, dissByPerm)
}

// VerifyOne is a VerifierFunc
func (kr KeyResolver) VerifyOne(ctx context.Context, perm Macaroon, diss []Macaroon) VerificationResult {
	key, trustedTPs, err := kr(ctx, perm.Nonce())
	if err != nil {
		return &FailedMacaroon{perm.Unverified(), err}
	}

	disMacs := make([]*macaroon.Macaroon, 0, len(diss))
	for _, d := range diss {
		disMacs = append(disMacs, d.UnsafeMacaroon())
	}

	if cavs, err := perm.UnsafeMacaroon().VerifyParsed(key, disMacs, trustedTPs); err != nil {
		return &FailedMacaroon{perm.Unverified(), err}
	} else {
		return &VerifiedMacaroon{perm.Unverified(), cavs}
	}
}

// VerificationCache is a Verifier that caches successful verification results.
type VerificationCache struct {
	verifier Verifier
	ttl      time.Duration
	cache    *lru.Cache[string, *cacheEntry]
}

func NewVerificationCache(verifier Verifier, ttl time.Duration, size int) *VerificationCache {
	cache, err := lru.New[string, *cacheEntry](size)
	if err != nil {
		panic(err)
	}

	return &VerificationCache{
		verifier: verifier,
		ttl:      ttl,
		cache:    cache,
	}
}

type cacheEntry struct {
	vm         *VerifiedMacaroon
	expiration time.Time
}

func (vc *VerificationCache) Verify(ctx context.Context, dissByPerm map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
	ret := make(map[Macaroon]VerificationResult, len(dissByPerm))
	hdrByPerm := make(map[Macaroon]string)

	for perm, diss := range dissByPerm {
		// sort discharges so we'll get the same cache key regardless of order
		slices.SortFunc(diss, func(a, b Macaroon) int { return strings.Compare(a.String(), b.String()) })

		hdr := String(append(diss, perm)...)

		if v, ok := vc.cache.Get(hdr); ok && v.expiration.After(time.Now()) {
			ret[perm] = v.vm
			delete(dissByPerm, perm)
		} else {
			hdrByPerm[perm] = hdr
		}
	}

	for perm, res := range vc.verifier.Verify(ctx, dissByPerm) {
		ret[perm] = res

		if vm, ok := res.(*VerifiedMacaroon); ok {
			vc.cache.Add(hdrByPerm[perm], &cacheEntry{
				vm,
				time.Now().Add(vc.ttl),
			})
		}
	}

	return ret
}

func (vc *VerificationCache) Purge() {
	vc.cache.Purge()
}

type VerifierFunc func(ctx context.Context, perm Macaroon, diss []Macaroon) VerificationResult

func (vf VerifierFunc) Verify(ctx context.Context, dissByPerm map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
	ret := make(map[Macaroon]VerificationResult, len(dissByPerm))

	for perm, diss := range dissByPerm {
		ret[perm] = vf(ctx, perm, diss)
	}

	return ret
}
