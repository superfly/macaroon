package auth

import (
	"fmt"
	"math"
	"time"

	"golang.org/x/exp/slices"

	"github.com/superfly/macaroon"
)

const (
	CavConfineUser         = macaroon.CavAuthConfineUser
	CavConfineOrganization = macaroon.CavAuthConfineOrganization
	CavConfineGoogleHD     = macaroon.CavAuthConfineGoogleHD
	CavConfineGitHubOrg    = macaroon.CavAuthConfineGitHubOrg
	CavMaxValidity         = macaroon.CavAuthMaxValidity
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
	case dr.Organization == nil:
		return c
	case !slices.Contains(dr.Organization.IDs, c.ID):
		return fmt.Errorf("%w (got %v)", c, dr.Organization.IDs)
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
	case dr.User == nil:
		return c
	case dr.User.ID != c.ID:
		return fmt.Errorf("%w (got %d)", c, dr.User.ID)
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
	case dr.Google == nil:
		return c
	case dr.Google.HD != string(*c):
		return fmt.Errorf("%w (got %s)", c, dr.Google.HD)
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
	case dr.GitHub == nil:
		return c
	case !slices.Contains(dr.GitHub.OrgIDs, uint64(*c)):
		return fmt.Errorf("%w (got %v)", c, dr.GitHub.OrgIDs)
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
