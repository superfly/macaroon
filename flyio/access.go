package flyio

import (
	"fmt"
	"strings"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

type Access struct {
	Action         resset.Action `json:"action,omitempty"`
	OrgID          *uint64       `json:"orgid,omitempty"`
	AppID          *uint64       `json:"appid,omitempty"`
	AppFeature     *string       `json:"app_feature,omitempty"`
	Feature        *string       `json:"feature,omitempty"`
	Volume         *string       `json:"volume,omitempty"`
	Machine        *string       `json:"machine,omitempty"`
	MachineFeature *string       `json:"machine_feature,omitempty"`
	Mutation       *string       `json:"mutation,omitempty"`
	SourceMachine  *string       `json:"sourceMachine,omitempty"`
	Cluster        *string       `json:"cluster,omitempty"`
	Command        []string      `json:"command,omitempty"`
}

var (
	_ macaroon.Access = (*Access)(nil)
	_ resset.Access   = (*Access)(nil)
)

func (a *Access) GetAction() resset.Action {
	return a.Action
}

func (a *Access) Now() time.Time {
	return time.Now()
}

// validate checks that the Access has sensible values set. This consists of
// ensuring that parent-resources are specified when child-resources are
// present (e.g. machine requires app requires org) and ensuring that multiple
// child resources aren't specified for a single parent resource (e.g. machine
// and volume are mutually exclusive).
//
// This ensure that a Access represents a single action taken on a single object.
func (f *Access) Validate() error {
	if f.OrgID == nil {
		return fmt.Errorf("%w org", resset.ErrResourceUnspecified)
	}

	// org-level resources = apps, features, storage objects
	var orgResources []string
	if f.AppID != nil {
		orgResources = append(orgResources, "app")
	}
	if f.Feature != nil {
		orgResources = append(orgResources, *f.Feature)
	}
	if len(orgResources) > 1 {
		return fmt.Errorf("%w: %s", resset.ErrResourcesMutuallyExclusive, strings.Join(orgResources, ", "))
	}

	// app-level resources = machines, volumes, app-features
	var appResources []string
	if f.Machine != nil {
		appResources = append(appResources, "machine")
	}
	if f.Volume != nil {
		appResources = append(appResources, "volume")
	}
	if f.AppFeature != nil {
		appResources = append(appResources, *f.AppFeature)
	}
	if len(appResources) != 0 && f.AppID == nil {
		return fmt.Errorf("%w app if app-owned resource is specified", resset.ErrResourceUnspecified)
	}
	if len(appResources) > 1 {
		return fmt.Errorf("%w: %s", resset.ErrResourcesMutuallyExclusive, strings.Join(appResources, ", "))
	}

	// lfsc feature-level resource = clusters
	if f.Cluster != nil {
		if f.Feature == nil {
			return fmt.Errorf("%w %s feature if clusters are specified", resset.ErrResourceUnspecified, FeatureLFSC)
		}

		if *f.Feature != FeatureLFSC {
			return fmt.Errorf("%w: clusters require the %s feature", macaroon.ErrInvalidAccess, FeatureLFSC)
		}
	}

	// machine feature requires machine
	var machineResources []string
	if f.Command != nil {
		machineResources = append(machineResources, "command-execution")
	}
	if f.MachineFeature != nil {
		machineResources = append(machineResources, *f.MachineFeature)
	}
	if len(machineResources) != 0 && f.Machine == nil {
		return fmt.Errorf("%w machine ", resset.ErrResourceUnspecified)
	}
	if len(machineResources) > 1 {
		return fmt.Errorf("%w: %s", resset.ErrResourcesMutuallyExclusive, strings.Join(machineResources, ", "))
	}

	return nil
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
	// MemberFeatures describes the level of access that non-admins are allowed
	// for various org features.
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

// PermittedRolesGetter is an interface for Accesses capable of indicating what
// roles are allowed for the operation.
type PermittedRolesGetter interface {
	macaroon.Access

	// GetPermittedRoles returns a slice of roles that are allowed to perform the
	// operation.
	GetPermittedRoles() []Role
}

var _ PermittedRolesGetter = (*Access)(nil)

// GetPermittedRoles implements macaroon.PermittedRolesGetter. We require RoleAdmin
// for unrecognized organization features or features for which the attempted
// action is not allowed by ordinary members.
func (a *Access) GetPermittedRoles() []Role {
	if a.Feature == nil {
		return []Role{RoleMember}
	}

	if memberAllowed, ok := MemberFeatures[*a.Feature]; ok && a.Action.IsSubsetOf(memberAllowed) {
		return []Role{RoleMember}
	}

	return []Role{RoleAdmin}
}

// OrgIDGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type OrgIDGetter interface {
	resset.Access
	GetOrgID() *uint64
}

var _ OrgIDGetter = (*Access)(nil)

// GetOrgID implements OrgIDGetter.
func (a *Access) GetOrgID() *uint64 { return a.OrgID }

// AppIDGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type AppIDGetter interface {
	resset.Access
	GetAppID() *uint64
}

var _ AppIDGetter = (*Access)(nil)

// GetAppID implements AppIDGetter.
func (a *Access) GetAppID() *uint64 { return a.AppID }

// AppFeatureGetter is an interface allowing other packages to implement
// Accesses that work with Caveats defined in this package.
type AppFeatureGetter interface {
	resset.Access
	GetAppFeature() *string
}

var _ AppFeatureGetter = (*Access)(nil)

// GetAppFeature implements AppFeatureGetter.
func (a *Access) GetAppFeature() *string { return a.AppFeature }

// FeatureGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type FeatureGetter interface {
	resset.Access
	GetFeature() *string
}

var _ FeatureGetter = (*Access)(nil)

// GetFeature implements FeatureGetter.
func (a *Access) GetFeature() *string { return a.Feature }

// VolumeGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type VolumeGetter interface {
	resset.Access
	GetVolume() *string
}

var _ VolumeGetter = (*Access)(nil)

// GetVolume implements VolumeGetter.
func (a *Access) GetVolume() *string { return a.Volume }

// MachineGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type MachineGetter interface {
	resset.Access
	GetMachine() *string
}

var _ MachineGetter = (*Access)(nil)

// GetMachine implements MachineGetter.
func (a *Access) GetMachine() *string { return a.Machine }

// MachineFeatureGetter is an interface allowing other packages to implement
// Accesses that work with Caveats defined in this package.
type MachineFeatureGetter interface {
	resset.Access
	GetMachineFeature() *string
}

var _ MachineFeatureGetter = (*Access)(nil)

// GetMachineFeature implements MachineFeatureGetter.
func (a *Access) GetMachineFeature() *string { return a.MachineFeature }

// MutationGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type MutationGetter interface {
	macaroon.Access
	GetMutation() *string
}

var _ MutationGetter = (*Access)(nil)

// GetMutation implements MutationGetter.
func (a *Access) GetMutation() *string { return a.Mutation }

// SourceMachineGetter is an interface allowing other packages to implement
// Accesses that work with Caveats defined in this package.
type SourceMachineGetter interface {
	macaroon.Access
	GetSourceMachine() *string
}

var _ SourceMachineGetter = (*Access)(nil)

// GetSourceMachine implements SourceMachineGetter.
func (a *Access) GetSourceMachine() *string { return a.SourceMachine }

// ClusterGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type ClusterGetter interface {
	resset.Access
	GetCluster() *string
}

var _ ClusterGetter = (*Access)(nil)

// GetCluster implements ClusterGetter.
func (a *Access) GetCluster() *string { return a.Cluster }

// CommandGetter is an interface allowing other packages to implement Accesses
// that work with Caveats defined in this package.
type CommandGetter interface {
	macaroon.Access
	GetCommand() []string
}

var _ CommandGetter = (*Access)(nil)

// GetCommand implements CommandGetter.
func (a *Access) GetCommand() []string { return a.Command }
