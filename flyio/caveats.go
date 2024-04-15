package flyio

import (
	"fmt"

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
	CavNoAdminFeatures   = macaroon.CavNoAdminFeatures
	CavCommands          = macaroon.CavFlyioCommands
	CavCommandsArgs      = macaroon.CavFlyioCommandsArgs
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
	case !f.GetAction().IsSubsetOf(c.Mask):
		return fmt.Errorf("%w access %s (%s not allowed)", resset.ErrUnauthorizedForAction, f.GetAction(), f.GetAction().Remove(c.Mask))
	default:
		return nil
	}
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
	f, isFlyioAccess := a.(AppIDGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt AppIDGetter", macaroon.ErrInvalidAccess)
	}
	return c.Apps.Prohibits(f.GetAppID(), f.GetAction())
}

type Volumes struct {
	Volumes resset.ResourceSet[string] `json:"volumes"`
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
	Machines resset.ResourceSet[string] `json:"machines"`
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
	Features resset.ResourceSet[string] `json:"features"`
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
	Features resset.ResourceSet[string] `json:"features"`
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
	Clusters resset.ResourceSet[string] `json:"clusters"`
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

const (
	FeatureWireGuard       = "wg"
	FeatureDomains         = "domain"
	FeatureSites           = "site"
	FeatureRemoteBuilders  = "builder"
	FeatureAddOns          = "addon"
	FeatureChecks          = "checks"
	FeatureLFSC            = "litefs-cloud"
	FeatureMembership      = "membership"
	FeatureBilling         = "billing"
	FeatureDeletion        = "deletion"
	FeatureDocumentSigning = "document_signing"
	FeatureAuthentication  = "authentication"
)

var (
	MemberFeatures = map[string]resset.Action{
		FeatureWireGuard:      resset.ActionAll,
		FeatureDomains:        resset.ActionAll,
		FeatureSites:          resset.ActionAll,
		FeatureRemoteBuilders: resset.ActionAll,
		FeatureAddOns:         resset.ActionAll,
		FeatureChecks:         resset.ActionAll,
		FeatureLFSC:           resset.ActionAll,

		FeatureMembership:     resset.ActionRead,
		FeatureBilling:        resset.ActionRead,
		FeatureAuthentication: resset.ActionRead,

		FeatureDeletion:        resset.ActionNone,
		FeatureDocumentSigning: resset.ActionNone,
	}
)

// NoAdminFeatures is a shorthand for specifying that the token isn't allowed to
// access admin-only features. Same as:
//
//	resset.IfPresent{
//	  Ifs: macaroon.NewCaveatSet(&FeatureSet{
//	    "memberFeatureOne": resset.ActionAll,
//	    "memberFeatureTwo": resset.ActionAll,
//	    "memberFeatureNNN": resset.ActionAll,
//	  }),
//	  Else: resset.ActionAll
//	}
type NoAdminFeatures struct{}

func init()                                                { macaroon.RegisterCaveatType(&NoAdminFeatures{}) }
func (c *NoAdminFeatures) CaveatType() macaroon.CaveatType { return CavNoAdminFeatures }
func (c *NoAdminFeatures) Name() string                    { return "NoAdminFeatures" }

func (c *NoAdminFeatures) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(FeatureGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt FeatureGetter", macaroon.ErrInvalidAccess)
	}
	if f.GetFeature() == nil {
		return nil
	}
	if *f.GetFeature() == "" {
		return fmt.Errorf("%w admin org features", resset.ErrUnauthorizedForResource)
	}

	memberPermission, ok := MemberFeatures[*f.GetFeature()]
	if !ok {
		return fmt.Errorf("%w %s", resset.ErrUnauthorizedForResource, *f.GetFeature())
	}
	if !f.GetAction().IsSubsetOf(memberPermission) {
		return fmt.Errorf(
			"%w %s access to %s",
			resset.ErrUnauthorizedForAction,
			f.GetAction().Remove(memberPermission),
			*f.GetFeature(),
		)
	}

	return nil
}

// Commands is a list of command names allowed by this token.
type Commands struct {
	Commands []string `json:"commands"`
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

	commandName := commandArgs[0]
	found := slices.Contains(c.Commands, commandName)
	if !found {
		return fmt.Errorf("%w commands %s", resset.ErrUnauthorizedForResource, commandArgs)
	}

	return nil
}

// CommandsArgs is a list of command argument vectors allowed by this token.
type CommandsArgs struct {
	Arguments [][]string `json:"arguments"`
}

func init()                                             { macaroon.RegisterCaveatType(&CommandsArgs{}) }
func (c *CommandsArgs) CaveatType() macaroon.CaveatType { return CavCommandsArgs }
func (c *CommandsArgs) Name() string                    { return "CommandsArgs" }

func (c *CommandsArgs) Prohibits(a macaroon.Access) error {
	f, isFlyioAccess := a.(CommandGetter)
	if !isFlyioAccess {
		return fmt.Errorf("%w: access isnt CommandGetter", macaroon.ErrInvalidAccess)
	}

	commandArgs := f.GetCommand()
	if commandArgs == nil {
		return fmt.Errorf("%w: only authorized for command execution", resset.ErrResourceUnspecified)
	}

	var found bool
	for _, allowedCommandArgs := range c.Arguments {
		if slices.Equal(commandArgs, allowedCommandArgs) {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("%w commands %s", resset.ErrUnauthorizedForResource, commandArgs)
	}

	return nil
}
