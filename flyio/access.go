package flyio

import (
	"fmt"
	"strings"
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
	// root-level resources = org
	if f.DeprecatedOrgID == nil && f.OrgSlug == nil {
		return fmt.Errorf("%w org", resset.ErrResourceUnspecified)
	}

	hasApp := f.DeprecatedAppID != nil || f.AppID != nil

	var orgLevelResources []string
	if hasApp {
		orgLevelResources = append(orgLevelResources, "app")
	}
	if f.Feature != nil {
		orgLevelResources = append(orgLevelResources, "org-feature")
	}
	if f.Cluster != nil {
		orgLevelResources = append(orgLevelResources, "litefs cluster")
	}
	if len(orgLevelResources) > 1 {
		return fmt.Errorf("%w: %s", macaroon.ErrResourcesMutuallyExclusive, strings.Join(orgLevelResources, ", "))
	}

	// app-level resources = machines, volumes
	if f.Machine != nil || f.Volume != nil {
		if !hasApp {
			return fmt.Errorf("%w app", resset.ErrResourceUnspecified)
		}

		if f.Machine != nil && f.Volume != nil {
			return fmt.Errorf("%w: volume, machine", macaroon.ErrResourcesMutuallyExclusive)
		}
	}

	// machine feature requires machine
	if f.MachineFeature != nil && f.Machine == nil {
		return fmt.Errorf("%w machine", resset.ErrResourceUnspecified)
	}

	return nil
}
