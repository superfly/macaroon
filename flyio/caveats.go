package flyio

import (
	"fmt"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resource_set"
)

const (
	CavOrganization        = 0
	CavVolumes             = 2
	CavApps                = 3
	CavFeatureSet          = 5
	CavMutations           = 6
	CavMachines            = 7
	CavConfineUser         = 8
	CavConfineOrganization = 9
	CavIsUser              = 10
	CavMachineFeatureSet   = 14
	CavFromMachineSource   = 15
	CavClusters            = 16
)

type notAttestation struct{}

func (a notAttestation) IsAttestation() bool { return false }

type FromMachine struct {
	ID             string `json:"id"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("FromMachineSource", CavFromMachineSource, &FromMachine{})
}

func (s *FromMachine) CaveatType() macaroon.CaveatType {
	return CavFromMachineSource
}

func (s *FromMachine) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)

	switch {
	case !isFlyioAccess:
		return macaroon.ErrInvalidAccess
	case f.SourceMachine == nil:
		return fmt.Errorf("%w missing SourceMachine", macaroon.ErrInvalidAccess)
	case s.ID != *f.SourceMachine:
		return fmt.Errorf("%w: unauthorized source, expected from machine %s, but got %s", macaroon.ErrUnauthorized, s.ID, *f.SourceMachine)
	default:
		return nil
	}
}

// Organization is an orgid, plus RWX-style access control.
type Organization struct {
	ID             uint64          `json:"id"`
	Mask           macaroon.Action `json:"mask"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("Organization", CavOrganization, &Organization{})
}

func (c *Organization) CaveatType() macaroon.CaveatType {
	return CavOrganization
}

func (c *Organization) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)

	switch {
	case !isFlyioAccess:
		return macaroon.ErrInvalidAccess
	case f.OrgID == 0:
		return fmt.Errorf("%w org", macaroon.ErrResourceUnspecified)
	case c.ID != f.OrgID:
		return fmt.Errorf("%w org %d, only %d", macaroon.ErrUnauthorizedForResource, f.OrgID, c.ID)
	case !f.Action.IsSubsetOf(c.Mask):
		return fmt.Errorf("%w access %s (%s not allowed)", macaroon.ErrUnauthorizedForAction, f.Action, f.Action.Remove(c.Mask))
	default:
		return nil
	}
}

// ConfineOrganization is a requirement placed on 3P caveats, requiring that the
// authenticated used be associated with OrgID. It has no meaning in a 1P setting.
type ConfineOrganization struct {
	ID             uint64 `json:"id"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("ConfineOrganization", CavConfineOrganization, &ConfineOrganization{})
}

func (c *ConfineOrganization) CaveatType() macaroon.CaveatType {
	return CavConfineOrganization
}

func (c *ConfineOrganization) Prohibits(macaroon.Access) error {
	// ConfineOrganization is only used in 3P caveats and has no role in access validation.
	return fmt.Errorf("%w (confine-organization)", macaroon.ErrBadCaveat)
}

// ConfineUser is a caveat limiting this token to a specific user ID.
type ConfineUser struct {
	ID             uint64 `json:"id"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("ConfineUser", CavConfineUser, &ConfineUser{})
}

func (c *ConfineUser) CaveatType() macaroon.CaveatType {
	return CavConfineUser
}

func (c *ConfineUser) Prohibits(macaroon.Access) error {
	// ConfineUser is only used in 3P caveats and has no role in access validation.
	return fmt.Errorf("%w (confine-user)", macaroon.ErrBadCaveat)
}

// Apps is a set of App caveats, with their RWX access levels. A token with this set can be used
// only with the listed apps, regardless of what the token says. Additional Apps can be added,
// but they can only narrow, not expand, which apps (or access levels) can be reached from the token.
type Apps struct {
	Apps           resource_set.ResourceSet[uint64] `json:"apps"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("Apps", CavApps, &Apps{})
}

func (c *Apps) CaveatType() macaroon.CaveatType {
	return CavApps
}

func (c *Apps) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Apps.Prohibits(f.AppID, f.Action)
}

type Volumes struct {
	Volumes        resource_set.ResourceSet[string] `json:"volumes"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("Volumes", CavVolumes, &Volumes{})
}

func (c *Volumes) CaveatType() macaroon.CaveatType {
	return CavVolumes
}

func (c *Volumes) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Volumes.Prohibits(f.Volume, f.Action)
}

type Machines struct {
	Machines       resource_set.ResourceSet[string] `json:"machines"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("Machines", CavMachines, &Machines{})
}

func (c *Machines) CaveatType() macaroon.CaveatType {
	return CavMachines
}

func (c *Machines) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Machines.Prohibits(f.Machine, f.Action)
}

type MachineFeatureSet struct {
	Features       resource_set.ResourceSet[string] `json:"features"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("MachineFeatureSet", CavMachineFeatureSet, &MachineFeatureSet{})
}

func (c *MachineFeatureSet) CaveatType() macaroon.CaveatType {
	return CavMachineFeatureSet
}

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
	Features       resource_set.ResourceSet[string] `json:"features"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("FeatureSet", CavFeatureSet, &FeatureSet{})
}

func (c *FeatureSet) CaveatType() macaroon.CaveatType {
	return CavFeatureSet
}

func (c *FeatureSet) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}
	return c.Features.Prohibits(f.Feature, f.Action)
}

// Mutations is a set of GraphQL mutations allowed by this token.
type Mutations struct {
	Mutations      []string `json:"mutations"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("Mutations", CavMutations, &Mutations{})
}

func (c *Mutations) CaveatType() macaroon.CaveatType {
	return CavMutations
}

func (c *Mutations) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}

	if f.Mutation == nil {
		// explicitly don't return macaroon.ErrResourceUnspecified. A mutation isn't a
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
		return fmt.Errorf("%w mutation %s", macaroon.ErrUnauthorizedForResource, *f.Mutation)
	}

	return nil
}

// TODO: deprecate this and replace with an attestation
type IsUser struct {
	ID             uint64 `json:"uint64"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("IsUser", CavIsUser, &IsUser{})
}

func (c *IsUser) CaveatType() macaroon.CaveatType {
	return CavIsUser
}

func (c *IsUser) Prohibits(a macaroon.Access) error {
	// IsUser is mostyly metadata and plays no role in access validation.
	return nil
}

// Clusters is a set of Cluster caveats, with their RWX access levels.
type Clusters struct {
	Clusters       resource_set.ResourceSet[string] `json:"clusters"`
	notAttestation `msgpack:"-" json:"-"`
}

func init() {
	macaroon.RegisterCaveatType("Clusters", CavClusters, &Clusters{})
}

func (c *Clusters) CaveatType() macaroon.CaveatType {
	return CavClusters
}

func (c *Clusters) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(*Access)
	if !isFlyioAccess {
		return macaroon.ErrInvalidAccess
	}

	return c.Clusters.Prohibits(f.Cluster, f.Action)
}
