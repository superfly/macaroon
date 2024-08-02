package storage

import (
	"context"
	"fmt"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/auth"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
)

// Authority is a token issuer/verifier.
type Authority struct {
	// Location is an identifier for the authority. Conventionally, it is the
	// URL of the service.
	Location string

	// SigningKey is the key used for minting new tokens.
	SigningKey macaroon.SigningKey

	// VerificationKeys is a map of keys that can be used to verify tokens. This
	// being separate from SigningKey allows for key rotation.
	VerificationKeys VerificationKeys

	// ThirdPartyEncryptionKeys are the keys to use when adding a third-party
	// caveat to a token. It is a map from the location of the third party
	// service to its key.
	ThirdPartyEncryptionKeys map[string]macaroon.EncryptionKey

	// ThirdPartyVerificationKeys is the keys to use when  verifying a
	// third-party caveats. This being separate from ThirdPartyEncryptionKeys
	// allows for key rotation.
	ThirdPartyVerificationKeys ThirdPartyVerificationKeys
}

func NewAuthority(location string, signingKey macaroon.SigningKey, thirdPartyKeys map[string]macaroon.EncryptionKey) *Authority {
	a := &Authority{
		Location:                   location,
		SigningKey:                 signingKey,
		VerificationKeys:           make(VerificationKeys),
		ThirdPartyEncryptionKeys:   thirdPartyKeys,
		ThirdPartyVerificationKeys: make(ThirdPartyVerificationKeys),
	}

	a.VerificationKeys.Add(signingKey)

	for loc, key := range thirdPartyKeys {
		a.ThirdPartyVerificationKeys.Add(loc, key)
	}

	return a
}

// IssueToken mints a new macaroon limited to performing the specified actions
// on objects in the specified bucket.
func (a *Authority) IssueBucketToken(action resset.Action, bucket string) (string, error) {
	keyID := calculateKeyID(a.SigningKey)

	mac, err := macaroon.New(keyID[:], a.Location, a.SigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to create macaroon: %w", err)
	}

	// construct a caveat limiting access to the specified bucket.
	prefix := resset.Prefix(a.Location + "/" + bucket)
	caveat := RestrictObjects(action, prefix)

	if err := mac.Add(caveat); err != nil {
		return "", fmt.Errorf("failed to add object restriction: %w", err)
	}

	return mac.String()
}

// IssueTokenForFlyioOrg mints a new macaroon limited to accessing buckets
// belonging to the specified fly.io organization. To be authenticated, the
// token must be accompanied by a discharge token from fly.io proving the that
// token bearer (user) is a member of the organization.
func (a *Authority) IssueTokenForFlyioOrg(thirdPartyLocation string, orgID uint64) (string, error) {
	keyID := calculateKeyID(a.SigningKey)

	mac, err := macaroon.New(keyID[:], a.Location, a.SigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to create macaroon: %w", err)
	}

	tpKey, ok := a.ThirdPartyEncryptionKeys[thirdPartyLocation]
	if !ok {
		return "", fmt.Errorf("unknown third party location: %s", thirdPartyLocation)
	}

	// This caveat is added to the third party ticket. It instructs the third
	// party (fly.io, in this case) to only issue a discharge token if the user
	// asking for the discharge is a member of the specified Fly.io
	// organization.
	orgCav := &auth.ConfineOrganization{ID: orgID}

	// This caveat instructs the third party to not issue discharge tokens that
	// are valid for more than one hour.
	mvCav := auth.MaxValidity(3600)

	if err := mac.Add3P(tpKey, thirdPartyLocation, orgCav, &mvCav); err != nil {
		return "", fmt.Errorf("failed to add third party caveat: %w", err)
	}

	// limit the token to accessing objects owned by the org.
	mac.Add(&flyio.Organization{
		ID:   orgID,
		Mask: resset.ActionAll,
	})

	return mac.String()
}

// CheckToken authenticates the provided token header and performs an authorization
// check against the provided access.
func (a *Authority) CheckToken(header string, access *Access) error {
	bun, err := bundle.ParseBundle(a.Location, header)
	if err != nil {
		return fmt.Errorf("malformed tokens: %w", err)
	}

	if _, err := bun.Verify(context.Background(), bundle.KeyResolver(a.resolveKey)); err != nil {
		return fmt.Errorf("no valid tokens: %w", err)
	}

	if err := bun.Validate(access); err != nil {
		return fmt.Errorf("no authorized tokens: %w", err)
	}

	return nil
}

// resolveKey is a bundle.KeyResolver.
func (a *Authority) resolveKey(_ context.Context, nonce macaroon.Nonce) (macaroon.SigningKey, map[string][]macaroon.EncryptionKey, error) {
	if key, ok := a.VerificationKeys.get(nonce.KID); ok {
		return key, a.ThirdPartyVerificationKeys, nil
	}

	return nil, nil, fmt.Errorf("unknown KID %x", nonce.KID)
}

// AttenuateToken adds caveats to the permission tokens in the provided token header.
func (a *Authority) AttenuateToken(header string, caveats ...macaroon.Caveat) (string, error) {
	bun, err := bundle.ParseBundle(a.Location, header)
	if err != nil {
		return "", fmt.Errorf("malformed tokens: %w", err)
	}

	if err := bun.Attenuate(caveats...); err != nil {
		return "", fmt.Errorf("failed to attenuate tokens: %w", err)
	}

	return bun.String(), nil
}
