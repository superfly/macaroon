package storage

import (
	"errors"
	"fmt"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/auth"
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
	toks, err := macaroon.Parse(header)
	if err != nil {
		return fmt.Errorf("failed to parse macaroon: %w", err)
	}

	// partition out permission and discharge tokens
	permissionMacaroons, _, _, dischargeTokens, err := macaroon.FindPermissionAndDischargeTokens(toks, a.Location)
	if err != nil {
		return fmt.Errorf("failed to find permission and discharge tokens: %w", err)
	}

	merr := errors.New("no valid tokens")

	for _, perm := range permissionMacaroons {
		var (
			nonce     = perm.Nonce
			errorBase = fmt.Errorf("token %s", nonce.UUID().String())
		)

		// lookup key to use for authenticating token
		key, ok := a.VerificationKeys.get(nonce.KID)
		if !ok {
			merr = errors.Join(merr, fmt.Errorf("%w: unknown key ID: %x", errorBase, nonce.KID))
			continue
		}

		// authenticate token
		verifiedCaveats, err := perm.Verify(key, dischargeTokens, a.ThirdPartyVerificationKeys)
		if err != nil {
			merr = errors.Join(merr, fmt.Errorf("%w: authentication failed: %w", errorBase, err))
			continue
		}

		// authorize token
		if err := verifiedCaveats.Validate(access); err != nil {
			merr = errors.Join(merr, fmt.Errorf("%w: macaroon authorization failed: %w", errorBase, err))
			continue
		}

		// found authenticated/authorized token
		return nil
	}

	return merr
}

// AttenuateToken adds caveats to the permission tokens in the provided token header.
func (a *Authority) AttenuateToken(header string, caveats ...macaroon.Caveat) (string, error) {
	toks, err := macaroon.Parse(header)
	if err != nil {
		return "", fmt.Errorf("failed to parse macaroon: %w", err)
	}

	// partition out permission and discharge tokens
	permissionMacaroons, _, _, dischargeTokens, err := macaroon.FindPermissionAndDischargeTokens(toks, a.Location)
	if err != nil {
		return "", fmt.Errorf("failed to find permission and discharge tokens: %w", err)
	}

	var attenuated [][]byte
	for _, perm := range permissionMacaroons {
		if err := perm.Add(caveats...); err != nil {
			return "", fmt.Errorf("failed to attenuate token: %w", err)
		}

		encoded, err := perm.Encode()
		if err != nil {
			return "", fmt.Errorf("failed to encode token: %w", err)
		}

		attenuated = append(attenuated, encoded)
	}

	return macaroon.ToAuthorizationHeader(append(attenuated, dischargeTokens...)...), nil
}
