package resset

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
)

func TestActionCaveat(t *testing.T) {
	cs := macaroon.NewCaveatSet(cavParent(ActionAll, 123), ptr(ActionRead))
	assert.NoError(t,
		cs.Validate(&testAccess{Action: ActionRead, ParentResource: ptr(uint64(123))}),
	)
	assert.IsError(t,
		cs.Validate(&testAccess{Action: ActionWrite, ParentResource: ptr(uint64(123))}),
		ErrUnauthorizedForAction,
	)
}
