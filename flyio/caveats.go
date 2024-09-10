package flyio

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

const (
	CavOrganization      = macaroon.CavFlyioOrganization
	CavVolumes           = macaroon.CavFlyioVolumes
	CavApps              = macaroon.CavFlyioApps
	CavFeatureSet        = macaroon.CavFlyioFeatureSet
	CavMutations         = macaroon.CavFlyioMutations
	CavMachines          = macaroon.CavFlyioMachines
	CavIsUser            = macaroon.CavFlyioIsUser
	CavMachineFeatureSet = macaroon.CavFlyioMachineFeatureSet
	CavFromMachineSource = macaroon.CavFlyioFromMachineSource
	CavClusters          = macaroon.CavFlyioClusters
	CavIsMember          = macaroon.CavFlyioIsMember
	CavCommands          = macaroon.CavFlyioCommands
	CavAppFeatureSet     = macaroon.CavFlyioAppFeatureSet
	CavStorageObjects    = macaroon.CavFlyioStorageObjects
	CavAllowedRoles      = macaroon.CavAllowedRoles
)

type FromMachine struct {
	ID string `json:"id"`
}

func init()                                            { macaroon.RegisterCaveatType(&FromMachine{}) }
func (c *FromMachine) CaveatType() macaroon.CaveatType { return CavFromMachineSource }
func (c *FromMachine) Name() string                    { return "FromMachineSource" }

func (c *FromMachine) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(SourceMachineGetter)

	switch {
	case !isFlyioAccess:
		return fmt.Errorf("%w: access isnt SourceMachineGetter", macaroon.ErrInvalidAccess)
	case f.GetSourceMachine() == nil:
		return fmt.Errorf("%w missing SourceMachine", macaroon.ErrInvalidAccess)
	case c.ID != *f.GetSourceMachine():
		return fmt.Errorf("%w: unauthorized source, expected from machine %s, but got %s", macaroon.ErrUnauthorized, c.ID, *f.GetSourceMachine())
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
	f, isFlyioAccess := a.(OrgIDGetter)

	switch {
	case !isFlyioAccess:
		return fmt.Errorf("%w: access isnt OrgIDGetter", macaroon.ErrInvalidAccess)
	case f.GetOrgID() == nil:
		return fmt.Errorf("%w org", resset.ErrResourceUnspecified)
	case c.ID != resset.ZeroID[uint64]() && c.ID != *f.GetOrgID():
		return fmt.Errorf("%w org %d, only %d", resset.ErrUnauthorizedForResource, *f.GetOrgID(), c.ID)
	case !resset.IsSubsetOf(f.GetAction(), c.Mask):
		return fmt.Errorf("%w access %s (%s not allowed)", resset.ErrUnauthorizedForAction, f.GetAction(), resset.Remove(f.GetAction(), c.Mask))
	default:
		return nil
	}
}

// Apps is a set of App caveats, with their RWX access levels. A token with this set can be used
// only with the listed apps, regardless of what the token says. Additional Apps can be added,
// but they can only narrow, not expand, which apps (or access levels) can be reached from the token.
type Apps struct {
	Apps resset.ResourceSet[uint64, resset.Action] `json:"apps"`
}

func init() {
	macaroon.RegisterCaveatType(&Apps{})
	macaroon.RegisterCaveatJSONAlias(CavApps, "DeprecatedApps")
}

func (c *Apps) CaveatType() macaroon.CaveatType { return CavApps }
func (c *Apps) Name() string                    { return "Apps" }

func (c *Apps) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(AppIDGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt AppIDGetter", macaroon.ErrInvalidAccess)
	}
	return c.Apps.Prohibits(f.GetAppID(), f.GetAction())
}

type Volumes struct {
	Volumes resset.ResourceSet[string, resset.Action] `json:"volumes"`
}

func init()                                        { macaroon.RegisterCaveatType(&Volumes{}) }
func (c *Volumes) CaveatType() macaroon.CaveatType { return CavVolumes }
func (c *Volumes) Name() string                    { return "Volumes" }

func (c *Volumes) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(VolumeGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt VolumeGetter", macaroon.ErrInvalidAccess)
	}
	return c.Volumes.Prohibits(f.GetVolume(), f.GetAction())
}

type Machines struct {
	Machines resset.ResourceSet[string, resset.Action] `json:"machines"`
}

func init()                                         { macaroon.RegisterCaveatType(&Machines{}) }
func (c *Machines) CaveatType() macaroon.CaveatType { return CavMachines }
func (c *Machines) Name() string                    { return "Machines" }

func (c *Machines) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(MachineGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt MachineGetter", macaroon.ErrInvalidAccess)
	}
	return c.Machines.Prohibits(f.GetMachine(), f.GetAction())
}

type MachineFeatureSet struct {
	Features resset.ResourceSet[string, resset.Action] `json:"features"`
}

func init()                                                  { macaroon.RegisterCaveatType(&MachineFeatureSet{}) }
func (c *MachineFeatureSet) CaveatType() macaroon.CaveatType { return CavMachineFeatureSet }
func (c *MachineFeatureSet) Name() string                    { return "MachineFeatureSet" }

func (c *MachineFeatureSet) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(MachineFeatureGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt MachineFeatureGetter", macaroon.ErrInvalidAccess)
	}
	return c.Features.Prohibits(f.GetMachineFeature(), f.GetAction())
}

// FeatureSet is a collection of organization-level "features" that are managed
// as single units. For example, the ability to manage wireguard networks is
// gated by the "wg" feature, though you could conceptually gate access to them
// individually with a Networks caveat. The feature name is free-form and more
// should be addded as it makes sense.
type FeatureSet struct {
	Features resset.ResourceSet[string, resset.Action] `json:"features"`
}

func init()                                           { macaroon.RegisterCaveatType(&FeatureSet{}) }
func (c *FeatureSet) CaveatType() macaroon.CaveatType { return CavFeatureSet }
func (c *FeatureSet) Name() string                    { return "FeatureSet" }

func (c *FeatureSet) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(FeatureGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt FeatureGetter", macaroon.ErrInvalidAccess)
	}
	return c.Features.Prohibits(f.GetFeature(), f.GetAction())
}

// Mutations is a set of GraphQL mutations allowed by this token.
type Mutations struct {
	Mutations []string `json:"mutations"`
}

func init()                                          { macaroon.RegisterCaveatType(&Mutations{}) }
func (c *Mutations) CaveatType() macaroon.CaveatType { return CavMutations }
func (c *Mutations) Name() string                    { return "Mutations" }

func (c *Mutations) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(MutationGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt MutationGetter", macaroon.ErrInvalidAccess)
	}

	if f.GetMutation() == nil {
		return fmt.Errorf("%w: only authorized for graphql mutations", resset.ErrResourceUnspecified)
	}

	var found bool
	for _, mutation := range c.Mutations {
		if mutation != *f.GetMutation() {
			continue
		}
		found = true
	}

	if !found {
		return fmt.Errorf("%w mutation %s", resset.ErrUnauthorizedForResource, *f.GetMutation())
	}

	return nil
}

// deprecated in favor of auth.FlyioUserID
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

// Clusters is a set of Cluster caveats, with their RWX access levels. Clusters
// belong to the "litefs-cloud" org-feature.
type Clusters struct {
	Clusters resset.ResourceSet[string, resset.Action] `json:"clusters"`
}

func init()                                         { macaroon.RegisterCaveatType(&Clusters{}) }
func (c *Clusters) CaveatType() macaroon.CaveatType { return CavClusters }
func (c *Clusters) Name() string                    { return "Clusters" }

func (c *Clusters) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(ClusterGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt ClusterGetter", macaroon.ErrInvalidAccess)
	}

	return c.Clusters.Prohibits(f.GetCluster(), f.GetAction())
}

// Role is used by the AllowedRoles and IsMember caveats.
type Role uint32

const (
	RoleMember Role = 1 << iota
	RoleBillingManager
	// add new roles here! don't forget to update roleNames

	RoleAdmin Role = 0xFFFFFFFF
)

var roleNames = map[Role]string{
	// put roles that are a combination of other roles at the top
	RoleAdmin: "admin",

	// put singular roles at the bottom
	RoleMember:         "member",
	RoleBillingManager: "billing_manager",
}

// HasAllRoles returns whether other is a subset of r.
func (r Role) HasAllRoles(other Role) bool {
	return r&other == other
}

func (r Role) String() string {
	if r == 0 {
		return "none"
	}

	if nr, ok := roleNames[r]; ok {
		return nr
	}

	var (
		names    []string
		combined Role
	)

	for namedRole, name := range roleNames {
		if r.HasAllRoles(namedRole) {
			names = append(names, name)
			combined |= namedRole

			if combined == r {
				slices.Sort(names) // for consistency in tests
				return strings.Join(names, "+")
			}
		}
	}

	return fmt.Sprintf("invalid(%d)", r)
}

// AllowedRoles is a bitmask of roles that may be assumed. Only usable with
// Accesses implementing PermittedRolesGetter. Checks that a role returned by
// [GetPermittedRoles] matches the mask.
type AllowedRoles Role

func init()                                             { macaroon.RegisterCaveatType(new(AllowedRoles)) }
func (c *AllowedRoles) CaveatType() macaroon.CaveatType { return CavAllowedRoles }
func (c *AllowedRoles) Name() string                    { return "AllowedRoles" }

func (c *AllowedRoles) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(PermittedRolesGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isn't PermittedRolesGetter", macaroon.ErrInvalidAccess)
	}

	permittedRoles := f.GetPermittedRoles()
	for _, permitted := range permittedRoles {
		if Role(*c).HasAllRoles(permitted) {
			return nil
		}
	}

	return fmt.Errorf("%w: allowed roles (%v) not permitted (%v)", ErrUnauthorizedForRole, *c, permittedRoles)
}

// IsMember is an alias for RoleMask(RoleMember). It used to be called
// NoAdminFeatures.
type IsMember struct{}

func init() {
	macaroon.RegisterCaveatType(&IsMember{})
	macaroon.RegisterCaveatJSONAlias(CavIsMember, "NoAdminFeatures")
}

func (c *IsMember) CaveatType() macaroon.CaveatType { return CavIsMember }
func (c *IsMember) Name() string                    { return "IsMember" }

func (c *IsMember) Prohibits(a macaroon.Access) error {
	ar := AllowedRoles(RoleMember)
	return ar.Prohibits(a)
}

// Commands is a list of commands allowed by this token.
// The zero value rejects any command.
type Commands []Command

// Command is a single command to allow. The zero value allows any command.
// If exact is true, the args must match exactly. Otherwise the args must
// match the prefix of the command being executed.
type Command struct {
	Args  []string `json:"args"`
	Exact bool     `json:"exact,omitempty"`
}

func init()                                         { macaroon.RegisterCaveatType(&Commands{}) }
func (c *Commands) CaveatType() macaroon.CaveatType { return CavCommands }
func (c *Commands) Name() string                    { return "Commands" }

func (c *Commands) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(CommandGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt CommandGetter", macaroon.ErrInvalidAccess)
	}

	commandArgs := f.GetCommand()
	if commandArgs == nil {
		return fmt.Errorf("%w: only authorized for command execution", resset.ErrResourceUnspecified)
	}

	var found bool
	allowedCommands := *c
	for _, allowedCommand := range allowedCommands {
		if len(allowedCommand.Args) > len(commandArgs) {
			continue
		}

		if allowedCommand.Exact && len(allowedCommand.Args) != len(commandArgs) {
			continue
		}

		if !slices.Equal(allowedCommand.Args, commandArgs[:len(allowedCommand.Args)]) {
			continue
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("%w commands %v", resset.ErrUnauthorizedForResource, commandArgs)
	}

	return nil
}

type AppFeatureSet struct {
	Features resset.ResourceSet[string, resset.Action] `json:"features"`
}

func init()                                              { macaroon.RegisterCaveatType(&AppFeatureSet{}) }
func (c *AppFeatureSet) CaveatType() macaroon.CaveatType { return CavAppFeatureSet }
func (c *AppFeatureSet) Name() string                    { return "AppFeatureSet" }

func (c *AppFeatureSet) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(AppFeatureGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt AppFeatureGetter", macaroon.ErrInvalidAccess)
	}
	return c.Features.Prohibits(f.GetAppFeature(), f.GetAction())
}

// StorageObjects limits what storage objects can be accessed. Objects are
// identified by a URL prefix string, so you can specify just the storage
// provider (e.g. `https://storage.fly/`), a specific bucket within a storage
// provider (e.g. `https://storage.fly/my_bucket`), or a object within a bucket
// (e.g. `https://storage.fly/my_bucket/my_file`).
type StorageObjects struct {
	Prefixes resset.ResourceSet[resset.Prefix, resset.Action] `json:"storage_objects"`
}

func init() {
	macaroon.RegisterCaveatType(&StorageObjects{})
}

func (c *StorageObjects) CaveatType() macaroon.CaveatType { return CavStorageObjects }
func (c *StorageObjects) Name() string                    { return "StorageObjects" }

func (c *StorageObjects) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(StorageObjectGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt StorageObjectGetter", macaroon.ErrInvalidAccess)
	}
	return c.Prefixes.Prohibits(f.GetStorageObject(), f.GetAction())
}
