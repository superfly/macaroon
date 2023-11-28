package flyio

import (
	"fmt"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

type Access struct {
	OrgSlug        *string       `json:"org_slug,omitempty"`
	AppID          *string       `json:"apphid,omitempty"`
	Action         resset.Action `json:"action,omitempty"`
	Feature        *string       `json:"feature,omitempty"`
	Volume         *string       `json:"volume,omitempty"`
	Machine        *string       `json:"machine,omitempty"`
	MachineFeature *string       `json:"machine_feature,omitempty"`
	Mutation       *string       `json:"mutation,omitempty"`
	SourceMachine  *string       `json:"sourceMachine,omitempty"`
	Cluster        *string       `json:"cluster,omitempty"`

	// deprecated
	DeprecatedOrgID *uint64 `json:"orgid,omitempty"`
	DeprecatedAppID *uint64 `json:"appid,omitempty"`
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
	// TODO: require both slug/id to be set once clients are updated.
	// root-level resources = org
	if f.DeprecatedOrgID == nil {
		return fmt.Errorf("%w org", resset.ErrResourceUnspecified)
	}

	// TODO: require both id/hid to be set once clients are updated.
	if f.AppID != nil && f.DeprecatedAppID == nil {
		return fmt.Errorf("%w deprecated app id if specifying app id", resset.ErrResourceUnspecified)
	}

	// org-level resources = apps, features
	if f.DeprecatedAppID != nil && f.Feature != nil {
		return fmt.Errorf("%w: app, org-feature", resset.ErrResourcesMutuallyExclusive)
	}

	// app-level resources = machines, volumes
	if f.Machine != nil || f.Volume != nil {
		if f.DeprecatedAppID == nil {
			return fmt.Errorf("%w app if app-owned resource is specified", resset.ErrResourceUnspecified)
		}

		if f.Machine != nil && f.Volume != nil {
			return fmt.Errorf("%w: volume, machine", resset.ErrResourcesMutuallyExclusive)
		}
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
	if f.MachineFeature != nil && f.Machine == nil {
		return fmt.Errorf("%w machine ", resset.ErrResourceUnspecified)
	}

	return nil
}
