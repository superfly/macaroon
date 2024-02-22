package resset

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
)

func TestCaveatSerialization(t *testing.T) {
	cs := macaroon.NewCaveatSet(
		&IfPresent{Ifs: macaroon.NewCaveatSet(&macaroon.ValidityWindow{NotBefore: 123, NotAfter: 234}), Else: ActionDelete},
		ptr(ActionRead),
	)

	b, err := json.Marshal(cs)
	assert.NoError(t, err)

	cs2 := macaroon.NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)

	b, err = encode(cs)
	assert.NoError(t, err)
	cs2, err = macaroon.DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)
}

const (
	cavTestParentResource = iota + macaroon.CavMinUserDefined + 10
	cavTestChildResource
)

type testCaveatParentResource struct {
	ID         uint64
	Permission Action
}

func cavParent(permission Action, id uint64) macaroon.Caveat {
	return &testCaveatParentResource{id, permission}
}

func init()                                                         { macaroon.RegisterCaveatType(&testCaveatParentResource{}) }
func (c *testCaveatParentResource) CaveatType() macaroon.CaveatType { return cavTestParentResource }
func (c *testCaveatParentResource) Name() string                    { return "ParentResource" }

func (c *testCaveatParentResource) Prohibits(f macaroon.Access) error {
	tf, isTestAccess := f.(*testAccess)

	switch {
	case !isTestAccess:
		return macaroon.ErrInvalidAccess
	case tf.ParentResource == nil:
		return ErrResourceUnspecified
	case *tf.ParentResource != c.ID:
		return fmt.Errorf("%w resource", ErrUnauthorizedForResource)
	case !tf.Action.IsSubsetOf(c.Permission):
		return fmt.Errorf("%w action", ErrUnauthorizedForAction)
	default:
		return nil
	}
}

type testCaveatChildResource struct {
	ID         uint64
	Permission Action
}

func cavChild(permission Action, id uint64) macaroon.Caveat {
	return &testCaveatChildResource{id, permission}
}

func init()                                                        { macaroon.RegisterCaveatType(&testCaveatChildResource{}) }
func (c *testCaveatChildResource) CaveatType() macaroon.CaveatType { return cavTestChildResource }
func (c *testCaveatChildResource) Name() string                    { return "ChildResource" }

func (c *testCaveatChildResource) Prohibits(f macaroon.Access) error {
	tf, isTestAccess := f.(*testAccess)

	switch {
	case !isTestAccess:
		return macaroon.ErrInvalidAccess
	case tf.ChildResource == nil:
		return ErrResourceUnspecified
	case *tf.ChildResource != c.ID:
		return fmt.Errorf("%w resource", ErrUnauthorizedForResource)
	case !tf.Action.IsSubsetOf(c.Permission):
		return fmt.Errorf("%w action", ErrUnauthorizedForAction)
	default:
		return nil
	}
}

type testAccess struct {
	Action         Action
	ParentResource *uint64
	ChildResource  *uint64
}

var _ Access = (*testAccess)(nil)

func (f *testAccess) GetAction() Action {
	return f.Action
}

func (f *testAccess) Now() time.Time {
	return time.Now()
}

func (f *testAccess) Validate() error {
	if f.ChildResource != nil && f.ParentResource == nil {
		return ErrResourceUnspecified
	}
	return nil
}
