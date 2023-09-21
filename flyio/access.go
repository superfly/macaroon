package flyio

import (
	"fmt"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

type Access struct {
	OrgID          uint64        `json:"orgid"`
	AppID          *uint64       `json:"appid"`
	Action         resset.Action `json:"action"`
	Feature        *string       `json:"feature"`
	Volume         *string       `json:"volume"`
	Machine        *string       `json:"machine"`
	MachineFeature *string       `json:"machine_feature"`
	Mutation       *string       `json:"mutation"`
	SourceMachine  *string       `json:"sourceMachine"`
	Cluster        *string       `json:"cluster"`
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
	if f.OrgID == 0 {
		return fmt.Errorf("%w org", resset.ErrResourceUnspecified)
	}

	// org-level resources = apps, features
	if f.AppID != nil && f.Feature != nil {
		return fmt.Errorf("%w: app, feature", macaroon.ErrResourcesMutuallyExclusive)
	}

	// app-level resources = machines, volumes
	if f.Machine != nil || f.Volume != nil {
		if f.AppID == nil {
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
