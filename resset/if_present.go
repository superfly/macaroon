package resset

import (
	"errors"
	"fmt"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/internal/merr"
)

// IfPresent attempts to apply the specified `Ifs` caveats if the relevant
// resources are specified. If none of the relevant resources are specified,
// the `Else` permission is applied.
//
// This is only meaningful to use with caveats that return macaroon
// ErrResourceUnspecified if the Access doesn't specify the resource
// constrained by the caveat. The Access must implement the resset.Access
// interface.
type IfPresent struct {
	Ifs  *macaroon.CaveatSet `json:"ifs"`
	Else Action              `json:"else"`
}

var _ macaroon.WrapperCaveat = (*IfPresent)(nil)

func init()                                          { macaroon.RegisterCaveatType(&IfPresent{}) }
func (c *IfPresent) CaveatType() macaroon.CaveatType { return macaroon.CavIfPresent }
func (c *IfPresent) Name() string                    { return "IfPresent" }

func (c *IfPresent) Prohibits(a macaroon.Access) error {
	ra, ok := a.(Access)
	if !ok {
		return macaroon.ErrInvalidAccess
	}

	var (
		err      error
		ifBranch bool
	)

	for _, cc := range c.Ifs.Caveats {
		// set err if any of the `Ifs` returns nil or a non-errResourceUnspecified error
		if cErr := cc.Prohibits(ra); !errors.Is(cErr, ErrResourceUnspecified) {
			err = merr.Append(err, cErr)
			ifBranch = true
		}
	}

	if !ifBranch && !ra.GetAction().IsSubsetOf(c.Else) {
		return fmt.Errorf("%w access %s (%s not allowed)", ErrUnauthorizedForAction, ra.GetAction(), ra.GetAction().Remove(c.Else))
	}

	return err
}

func (c *IfPresent) IsAttestation() bool { return false }

func (c *IfPresent) Unwrap() *macaroon.CaveatSet {
	return c.Ifs
}
