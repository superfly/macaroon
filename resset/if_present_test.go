package resset

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
)

func TestIfPresent(t *testing.T) {
	var (
		cavs []macaroon.Caveat
	)

	no := func(expected error, f Access) {
		t.Helper()
		err := macaroon.NewCaveatSet(cavs...).Validate(f)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, expected))
	}

	yes := func(f Access) {
		t.Helper()
		assert.NoError(t, macaroon.NewCaveatSet(cavs...).Validate(f))
	}

	cavs = []macaroon.Caveat{
		cavParent(ActionRead|ActionWrite|ActionCreate|ActionDelete, 123),
		&IfPresent{
			Ifs:  macaroon.NewCaveatSet(cavChild(ActionRead|ActionDelete|ActionControl, 234)),
			Else: ActionRead | ActionCreate,
		},
	}

	// failing before IfPresent
	no(ErrResourceUnspecified, &testAccess{ChildResource: ptr(uint64(234)), Action: ActionRead})                                       // no parent
	no(ErrUnauthorizedForResource, &testAccess{ParentResource: ptr(uint64(987)), ChildResource: ptr(uint64(234)), Action: ActionRead}) // bad parent

	// hit if block (success)
	yes(&testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(234)), Action: ActionRead | ActionDelete})

	// hit if block (failure)
	no(ErrUnauthorizedForResource, &testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(876)), Action: ActionRead})  // wrong child
	no(ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(234)), Action: ActionWrite})   // action disallowed by child caveat
	no(ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(234)), Action: ActionControl}) // action disallowed by parent caveat

	// hit else block (success)
	yes(&testAccess{ParentResource: ptr(uint64(123)), Action: ActionRead | ActionCreate})

	// hit else block (failure)
	no(ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), Action: ActionWrite})   // action allowed earlier, disallowed by else
	no(ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), Action: ActionControl}) // action only allowed by if
}

func TestCaveatSerialization(t *testing.T) {
	cs := macaroon.NewCaveatSet(
		&IfPresent{Ifs: macaroon.NewCaveatSet(&macaroon.ValidityWindow{NotBefore: 123, NotAfter: 234}), Else: ActionDelete},
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
