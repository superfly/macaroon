package auth

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"golang.org/x/exp/slices"

	"github.com/superfly/macaroon"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	CavConfineUser          = macaroon.CavAuthConfineUser
	CavConfineOrganization  = macaroon.CavAuthConfineOrganization
	CavConfineGoogleHD      = macaroon.CavAuthConfineGoogleHD
	CavConfineGitHubOrg     = macaroon.CavAuthConfineGitHubOrg
	CavMaxValidity          = macaroon.CavAuthMaxValidity
	AttestationFlyioUserID  = macaroon.AttestationAuthFlyioUserID
	AttestationGitHubUserID = macaroon.AttestationAuthGitHubUserID
	AttestationGoogleUserID = macaroon.AttestationAuthGoogleUserID
)

// ConfineOrganization is a requirement placed on 3P caveats, requiring that the
// authenticated used be associated with OrgID. It has no meaning in a 1P setting.
type ConfineOrganization struct {
	ID uint64 `json:"id"`
}

func RequireOrganization(id uint64) *ConfineOrganization {
	return &ConfineOrganization{id}
}

// Implements macaroon.Caveat
func init()                                                    { macaroon.RegisterCaveatType(&ConfineOrganization{}) }
func (c *ConfineOrganization) CaveatType() macaroon.CaveatType { return CavConfineOrganization }
func (c *ConfineOrganization) Name() string                    { return "ConfineOrganization" }

// Implements macaroon.Caveat
func (c *ConfineOrganization) Prohibits(a macaroon.Access) error {
	switch dr, isDR := a.(*DischargeRequest); {
	case !isDR:
		return macaroon.ErrInvalidAccess
	case len(dr.Flyio) == 0:
		return c
	case !slices.Contains(dr.FlyioOrganizationIDs(), c.ID):
		return fmt.Errorf("%w (got %v)", c, dr.FlyioOrganizationIDs())
	default:
		return nil
	}
}

// implements error
func (c *ConfineOrganization) Error() string {
	return fmt.Sprintf("must authenticate with Fly.io account with access to organization %d", c.ID)
}

// ConfineUser is a caveat limiting this token to a specific user ID.
type ConfineUser struct {
	ID uint64 `json:"id"`
}

func RequireUser(id uint64) *ConfineUser {
	return &ConfineUser{id}
}

// Implements macaroon.Caveat
func init()                                            { macaroon.RegisterCaveatType(&ConfineUser{}) }
func (c *ConfineUser) CaveatType() macaroon.CaveatType { return CavConfineUser }
func (c *ConfineUser) Name() string                    { return "ConfineUser" }

// Implements macaroon.Caveat
func (c *ConfineUser) Prohibits(a macaroon.Access) error {
	switch dr, isDR := a.(*DischargeRequest); {
	case !isDR:
		return macaroon.ErrInvalidAccess
	case len(dr.Flyio) == 0:
		return c
	case !slices.Contains(dr.FlyioUserIDs(), c.ID):
		return fmt.Errorf("%w (got %v)", c, dr.FlyioUserIDs())
	default:
		return nil
	}
}

// implements error
func (c *ConfineUser) Error() string {
	return fmt.Sprintf("must authenticate with Fly.io account %d", c.ID)
}

// Implements macaroon.Caveat and error. Requires that the user is
// authenticated to Google with an account in the specified HD.
type ConfineGoogleHD string

func RequireGoogleHD(hd string) *ConfineGoogleHD {
	return (*ConfineGoogleHD)(&hd)
}

// Implements macaroon.Caveat
func init()                                                { macaroon.RegisterCaveatType(new(ConfineGoogleHD)) }
func (c *ConfineGoogleHD) CaveatType() macaroon.CaveatType { return CavConfineGoogleHD }
func (c *ConfineGoogleHD) Name() string                    { return "ConfineGoogleHD" }

// Implements macaroon.Caveat
func (c *ConfineGoogleHD) Prohibits(a macaroon.Access) error {
	switch dr, isDR := a.(*DischargeRequest); {
	case !isDR:
		return macaroon.ErrInvalidAccess
	case len(dr.Google) == 0:
		return c
	case !slices.Contains(dr.GoogleHDs(), (string)(*c)):
		return fmt.Errorf("%w (got %v)", c, dr.GoogleHDs())
	default:
		return nil
	}
}

// implements error
func (c *ConfineGoogleHD) Error() string {
	return fmt.Sprintf("must authenticate with %s Google account", string(*c))
}

// Implements macaroon.Caveat and error. Requires that the user is
// authenticated to GitHub with an account that has access the specified org.
type ConfineGitHubOrg uint64

func RequireGitHubOrg(id uint64) *ConfineGitHubOrg {
	return (*ConfineGitHubOrg)(&id)
}

// Implements macaroon.Caveat
func init()                                                 { macaroon.RegisterCaveatType(new(ConfineGitHubOrg)) }
func (c *ConfineGitHubOrg) CaveatType() macaroon.CaveatType { return CavConfineGitHubOrg }
func (c *ConfineGitHubOrg) Name() string                    { return "ConfineGitHubOrg" }

// Implements macaroon.Caveat
func (c *ConfineGitHubOrg) Prohibits(a macaroon.Access) error {
	switch dr, isDR := a.(*DischargeRequest); {
	case !isDR:
		return macaroon.ErrInvalidAccess
	case len(dr.GitHub) == 0:
		return c
	case !slices.Contains(dr.GitHubOrgIDs(), uint64(*c)):
		return fmt.Errorf("%w (got %v)", c, dr.GitHubOrgIDs())
	default:
		return nil
	}
}

// implements error
func (c *ConfineGitHubOrg) Error() string {
	return fmt.Sprintf("must authenticate with GitHub account with access to organization %d", uint64(*c))
}

// Implements macaroon.Caveat. Limits the validity window length (seconds) of
// discharges issued by 3ps.
type MaxValidity uint64

// Implements macaroon.Caveat
func init()                                            { macaroon.RegisterCaveatType(new(MaxValidity)) }
func (c *MaxValidity) CaveatType() macaroon.CaveatType { return CavMaxValidity }
func (c *MaxValidity) Name() string                    { return "MaxValidity" }

// Implements macaroon.Caveat
func (c *MaxValidity) Prohibits(a macaroon.Access) error {
	switch aa, isAuthAccess := a.(*DischargeRequest); {
	case !isAuthAccess:
		return macaroon.ErrInvalidAccess
	case aa.Expiry.Sub(aa.Now()) > c.duration():
		return fmt.Errorf(
			"%w: %v exceeds max validity window (%v)",
			macaroon.ErrUnauthorized,
			aa.Expiry.Sub(aa.Now()),
			c.duration(),
		)
	default:
		return nil
	}
}

func (c *MaxValidity) duration() time.Duration {
	return time.Duration(*c) * time.Second
}

func GetMaxValidity(cs *macaroon.CaveatSet) (time.Duration, bool) {
	max := time.Duration(math.MaxInt64)

	for _, cav := range macaroon.GetCaveats[*MaxValidity](cs) {
		if cavDur := cav.duration(); max > cavDur {
			max = cavDur
		}
	}

	return max, max != time.Duration(math.MaxInt64)
}

type FlyioUserID uint64

func init()                                              { macaroon.RegisterCaveatType(new(FlyioUserID)) }
func (c *FlyioUserID) CaveatType() macaroon.CaveatType   { return AttestationFlyioUserID }
func (c *FlyioUserID) Name() string                      { return "FlyioUserID" }
func (c *FlyioUserID) Prohibits(a macaroon.Access) error { return macaroon.ErrBadCaveat }
func (c *FlyioUserID) IsAttestation() bool               { return true }

type GitHubUserID uint64

func init()                                               { macaroon.RegisterCaveatType(new(GitHubUserID)) }
func (c *GitHubUserID) CaveatType() macaroon.CaveatType   { return AttestationGitHubUserID }
func (c *GitHubUserID) Name() string                      { return "GitHubUserID" }
func (c *GitHubUserID) Prohibits(a macaroon.Access) error { return macaroon.ErrBadCaveat }
func (c *GitHubUserID) IsAttestation() bool               { return true }

type GoogleUserID big.Int

func init()                                               { macaroon.RegisterCaveatType(new(GoogleUserID)) }
func (c *GoogleUserID) CaveatType() macaroon.CaveatType   { return AttestationGoogleUserID }
func (c *GoogleUserID) Name() string                      { return "GoogleUserID" }
func (c *GoogleUserID) Prohibits(a macaroon.Access) error { return macaroon.ErrBadCaveat }
func (c *GoogleUserID) IsAttestation() bool               { return true }

func (c *GoogleUserID) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode((*big.Int)(c).Bytes())
}

func (c *GoogleUserID) DecodeMsgpack(dec *msgpack.Decoder) error {
	b, err := dec.DecodeBytes()
	if err != nil {
		return err
	}

	(*big.Int)(c).SetBytes(b)
	return nil
}

func (c *GoogleUserID) MarshalJSON() ([]byte, error) {
	return []byte((*big.Int)(c).String()), nil
}

func (c *GoogleUserID) UnmarshalJSON(data []byte) error {
	if _, ok := (*big.Int)(c).SetString(string(data), 10); !ok {
		return errors.New("bad bigint")
	}
	return nil
}
