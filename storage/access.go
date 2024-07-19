package storage

import (
	"errors"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
)

// Access describes an attempt to access a storage object.
type Access struct {
	Action resset.Action
	Object resset.Prefix

	// if a storage service wanted to use macaroons for limiting access to
	// buckets not associated with fly.io organizations, this could be a *uint64
	// instead. They would have to be careful when issuing macaroons though to
	// not accidentally allow access to buckets not associated with an org.
	FlyioOrganizationID uint64
}

var (
	_ macaroon.Access   = (*Access)(nil)
	_ flyio.OrgIDGetter = (*Access)(nil)
)

// implements macaroon.Access
func (*Access) Now() time.Time { return time.Now() }

// implements macaroon.Access
func (a *Access) Validate() error {
	switch {
	case a.Object == "":
		return errors.New("missing Object in Access")
	case a.FlyioOrganizationID == 0:
		return errors.New("missing FlyioOrganizationID in Access")
	default:
		return nil
	}
}

// GetAction implements resset.Access
func (a *Access) GetAction() resset.Action { return a.Action }

// GetOrgID implements flyio.OrgIDGetter.
func (a *Access) GetOrgID() *uint64 { return &a.FlyioOrganizationID }
