package resset

import (
	"encoding/json"
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

func TestActionSerialization(t *testing.T) {
	highest := ActionDecrypt << 1
	for act := Action(0); act < highest; act += 1 {
		bs, err := json.Marshal(&act)
		assert.NoError(t, err)

		var act2 Action
		err = json.Unmarshal(bs, &act2)
		assert.NoError(t, err)
		assert.Equal(t, act, act2)
	}
}
