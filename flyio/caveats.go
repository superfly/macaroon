package flyio

import (
	"fmt"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

const (
	CavOrganization        = macaroon.CavFlyioOrganization
	CavVolumes             = macaroon.CavFlyioVolumes
	CavApps                = macaroon.CavFlyioApps
	CavFeatureSet          = macaroon.CavFlyioFeatureSet
	CavMutations           = macaroon.CavFlyioMutations
	CavMachines            = macaroon.CavFlyioMachines
	CavConfineUser         = macaroon.CavFlyioConfineUser
	CavConfineOrganization = macaroon.CavFlyioConfineOrganization
	CavIsUser              = macaroon.CavFlyioIsUser
	CavMachineFeatureSet   = macaroon.CavFlyioMachineFeatureSet
	CavFromMachineSource   = macaroon.CavFlyioFromMachineSource
	CavClusters            = macaroon.CavFlyioClusters
)

type FromMachine struct {
	ID string `json:"id"`
}

func init()                                            { macaroon.RegisterCaveatType(&FromMachine{}) }
func (c *FromMachine) CaveatType() macaroon.CaveatType { return CavFromMachineSource }
func (c *FromMachine) Name() string                    { return "FromMachineSource" }

func (c *FromMachine) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)

	switch {
	case !isFlyioAccess:
		return macaroon.ErrInvalidAccess
	case f.SourceMachine == nil:
		return fmt.Errorf("%w missing SourceMachine", macaroon.ErrInvalidAccess)
	case c.ID != *f.SourceMachine:
		return fmt.Errorf("%w: unauthorized source, expected from machine %s, but got %s", macaroon.ErrUnauthorized, c.ID, *f.SourceMachine)
	default:
		return nil
	}
}

// Organization is an orgid, plus RWX-style access control.
type Organization struct {
	ID   uint64        `json:"id"`
	Mask resset.Action `json:"mask"`
}

func init() {
	macaroon.RegisterCaveatType(&Organization{})
	macaroon.RegisterCaveatJSONAlias(CavOrganization, "DeprecatedOrganization")
}

func (c *Organization) CaveatType() macaroon.CaveatType { return CavOrganization }
func (c *Organization) Name() string                    { return "Organization" }

func (c *Organization) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)

	switch {
	case !isFlyioAccess:
		return macaroon.ErrInvalidAccess
	case f.DeprecatedOrgID == nil:
		return fmt.Errorf("%w org", resset.ErrResourceUnspecified)
	case c.ID != *f.DeprecatedOrgID:
		return fmt.Errorf("%w org %d, only %d", resset.ErrUnauthorizedForResource, f.DeprecatedOrgID, c.ID)
	case !f.Action.IsSubsetOf(c.Mask):
		return fmt.Errorf("%w access %s (%s not allowed)", resset.ErrUnauthorizedForAction, f.Action, f.Action.Remove(c.Mask))
	default:
		return nil
	}
}

// ConfineOrganization is a requirement placed on 3P caveats, requiring that the
// authenticated used be associated with OrgID. It has no meaning in a 1P setting.
type ConfineOrganization struct {
	ID uint64 `json:"id"`
}

func init()                                                    { macaroon.RegisterCaveatType(&ConfineOrganization{}) }
func (c *ConfineOrganization) CaveatType() macaroon.CaveatType { return CavConfineOrganization }
func (c *ConfineOrganization) Name() string                    { return "ConfineOrganization" }

func (c *ConfineOrganization) Prohibits(macaroon.Access) error {
	// ConfineOrganization is only used in 3P caveats and has no role in access validation.
	return fmt.Errorf("%w (confine-organization)", macaroon.ErrBadCaveat)
}

// ConfineUser is a caveat limiting this token to a specific user ID.
type ConfineUser struct {
	ID uint64 `json:"id"`
}

func init()                                            { macaroon.RegisterCaveatType(&ConfineUser{}) }
func (c *ConfineUser) CaveatType() macaroon.CaveatType { return CavConfineUser }
func (c *ConfineUser) Name() string                    { return "ConfineUser" }

func (c *ConfineUser) Prohibits(macaroon.Access) error {
	// ConfineUser is only used in 3P caveats and has no role in access validation.
	return fmt.Errorf("%w (confine-user)", macaroon.ErrBadCaveat)
}

// Apps is a set of App caveats, with their RWX access levels. A token with this set can be used
// only with the listed apps, regardless of what the token says. Additional Apps can be added,
// but they can only narrow, not expand, which apps (or access levels) can be reached from the token.
type Apps struct {
	Apps resset.ResourceSet[uint64] `json:"apps"`
}

func init() {
	macaroon.RegisterCaveatType(&Apps{})
	macaroon.RegisterCaveatJSONAlias(CavApps, "DeprecatedApps")
}

func (c *Apps) CaveatType() macaroon.CaveatType { return CavApps }
func (c *Apps) Name() string                    { return "Apps" }

func (c *Apps) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Apps.Prohibits(f.DeprecatedAppID, f.Action)
}

type Volumes struct {
	Volumes resset.ResourceSet[string] `json:"volumes"`
}

func init()                                        { macaroon.RegisterCaveatType(&Volumes{}) }
func (c *Volumes) CaveatType() macaroon.CaveatType { return CavVolumes }
func (c *Volumes) Name() string                    { return "Volumes" }

func (c *Volumes) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Volumes.Prohibits(f.Volume, f.Action)
}

type Machines struct {
	Machines resset.ResourceSet[string] `json:"machines"`
}

func init()                                         { macaroon.RegisterCaveatType(&Machines{}) }
func (c *Machines) CaveatType() macaroon.CaveatType { return CavMachines }
func (c *Machines) Name() string                    { return "Machines" }

func (c *Machines) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Machines.Prohibits(f.Machine, f.Action)
}

type MachineFeatureSet struct {
	Features resset.ResourceSet[string] `json:"features"`
}

func init()                                                  { macaroon.RegisterCaveatType(&MachineFeatureSet{}) }
func (c *MachineFeatureSet) CaveatType() macaroon.CaveatType { return CavMachineFeatureSet }
func (c *MachineFeatureSet) Name() string                    { return "MachineFeatureSet" }

func (c *MachineFeatureSet) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Features.Prohibits(f.MachineFeature, f.Action)
}

// FeatureSet is a collection of organization-level "features" that are managed
// as single units. For example, the ability to manage wireguard networks is
// gated by the "wg" feature, though you could conceptually gate access to them
// individually with a Networks caveat. The feature name is free-form and more
// should be addded as it makes sense.
type FeatureSet struct {
	Features resset.ResourceSet[string] `json:"features"`
}

func init()                                           { macaroon.RegisterCaveatType(&FeatureSet{}) }
func (c *FeatureSet) CaveatType() macaroon.CaveatType { return CavFeatureSet }
func (c *FeatureSet) Name() string                    { return "FeatureSet" }

func (c *FeatureSet) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Features.Prohibits(f.Feature, f.Action)
}

// Mutations is a set of GraphQL mutations allowed by this token.
type Mutations struct {
	Mutations []string `json:"mutations"`
}

func init()                                          { macaroon.RegisterCaveatType(&Mutations{}) }
func (c *Mutations) CaveatType() macaroon.CaveatType { return CavMutations }
func (c *Mutations) Name() string                    { return "Mutations" }

func (c *Mutations) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}

	if f.Mutation == nil {
		// explicitly don't return resset.ErrResourceUnspecified. A mutation isn't a
		// resource and can't be used with IfPresent caveats.
		return fmt.Errorf("%w: only authorized for graphql mutations", macaroon.ErrUnauthorized)
	}

	var found bool
	for _, mutation := range c.Mutations {
		if mutation != *f.Mutation {
			continue
		}
		found = true
	}

	if !found {
		return fmt.Errorf("%w mutation %s", resset.ErrUnauthorizedForResource, *f.Mutation)
	}

	return nil
}

// TODO: deprecate this and replace with an attestation
type IsUser struct {
	ID uint64 `json:"uint64"`
}

func init()                                       { macaroon.RegisterCaveatType(&IsUser{}) }
func (c *IsUser) CaveatType() macaroon.CaveatType { return CavIsUser }
func (c *IsUser) Name() string                    { return "IsUser" }

func (c *IsUser) Prohibits(a macaroon.Access) error {
	// IsUser is mostyly metadata and plays no role in access validation.
	return nil
}

// Clusters is a set of Cluster caveats, with their RWX access levels.
type Clusters struct {
	Clusters resset.ResourceSet[string] `json:"clusters"`
}

func init()                                         { macaroon.RegisterCaveatType(&Clusters{}) }
func (c *Clusters) CaveatType() macaroon.CaveatType { return CavClusters }
func (c *Clusters) Name() string                    { return "Clusters" }

func (c *Clusters) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}

	return c.Clusters.Prohibits(f.Cluster, f.Action)
}
