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
		cavParent(macaroon.ActionRead|macaroon.ActionWrite|macaroon.ActionCreate|macaroon.ActionDelete, 123),
		&IfPresent{
			Ifs:  macaroon.NewCaveatSet(cavChild(macaroon.ActionRead|macaroon.ActionDelete|macaroon.ActionControl, 234)),
			Else: macaroon.ActionRead | macaroon.ActionCreate,
		},
	}

	// failing before IfPresent
	no(macaroon.ErrResourceUnspecified, &testAccess{ChildResource: ptr(uint64(234)), Action: macaroon.ActionRead})                                       // no parent
	no(macaroon.ErrUnauthorizedForResource, &testAccess{ParentResource: ptr(uint64(987)), ChildResource: ptr(uint64(234)), Action: macaroon.ActionRead}) // bad parent

	// hit if block (success)
	yes(&testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(234)), Action: macaroon.ActionRead | macaroon.ActionDelete})

	// hit if block (failure)
	no(macaroon.ErrUnauthorizedForResource, &testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(876)), Action: macaroon.ActionRead})  // wrong child
	no(macaroon.ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(234)), Action: macaroon.ActionWrite})   // action disallowed by child caveat
	no(macaroon.ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), ChildResource: ptr(uint64(234)), Action: macaroon.ActionControl}) // action disallowed by parent caveat

	// hit else block (success)
	yes(&testAccess{ParentResource: ptr(uint64(123)), Action: macaroon.ActionRead | macaroon.ActionCreate})

	// hit else block (failure)
	no(macaroon.ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), Action: macaroon.ActionWrite})   // action allowed earlier, disallowed by else
	no(macaroon.ErrUnauthorizedForAction, &testAccess{ParentResource: ptr(uint64(123)), Action: macaroon.ActionControl}) // action only allowed by if
}

func TestCaveatSerialization(t *testing.T) {
	cs := macaroon.NewCaveatSet(
		&IfPresent{Ifs: macaroon.NewCaveatSet(&macaroon.ValidityWindow{NotBefore: 123, NotAfter: 234}), Else: macaroon.ActionDelete},
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
	Permission macaroon.Action
}

func init() {
	macaroon.RegisterCaveatType("ParentResource", cavTestParentResource, &testCaveatParentResource{})
}

func cavParent(permission macaroon.Action, id uint64) macaroon.Caveat {
	return &testCaveatParentResource{id, permission}
}

func (c *testCaveatParentResource) CaveatType() macaroon.CaveatType {
	return cavTestParentResource
}

func (c *testCaveatParentResource) Prohibits(f macaroon.Access) error {
	tf, isTestAccess := f.(*testAccess)

	switch {
	case !isTestAccess:
		return macaroon.ErrInvalidAccess
	case tf.ParentResource == nil:
		return macaroon.ErrResourceUnspecified
	case *tf.ParentResource != c.ID:
		return fmt.Errorf("%w resource", macaroon.ErrUnauthorizedForResource)
	case !tf.Action.IsSubsetOf(c.Permission):
		return fmt.Errorf("%w action", macaroon.ErrUnauthorizedForAction)
	default:
		return nil
	}
}

func (c *testCaveatParentResource) IsAttestation() bool {
	return false
}

type testCaveatChildResource struct {
	ID         uint64
	Permission macaroon.Action
}

func init() {
	macaroon.RegisterCaveatType("ChildResource", cavTestChildResource, &testCaveatChildResource{})
}

func cavChild(permission macaroon.Action, id uint64) macaroon.Caveat {
	return &testCaveatChildResource{id, permission}
}

func (c *testCaveatChildResource) CaveatType() macaroon.CaveatType {
	return cavTestChildResource
}

func (c *testCaveatChildResource) Prohibits(f macaroon.Access) error {
	tf, isTestAccess := f.(*testAccess)

	switch {
	case !isTestAccess:
		return macaroon.ErrInvalidAccess
	case tf.ChildResource == nil:
		return macaroon.ErrResourceUnspecified
	case *tf.ChildResource != c.ID:
		return fmt.Errorf("%w resource", macaroon.ErrUnauthorizedForResource)
	case !tf.Action.IsSubsetOf(c.Permission):
		return fmt.Errorf("%w action", macaroon.ErrUnauthorizedForAction)
	default:
		return nil
	}
}

func (c *testCaveatChildResource) IsAttestation() bool {
	return false
}

type testAccess struct {
	Action         macaroon.Action
	ParentResource *uint64
	ChildResource  *uint64
}

var _ Access = (*testAccess)(nil)

func (f *testAccess) GetAction() macaroon.Action {
	return f.Action
}

func (f *testAccess) Now() time.Time {
	return time.Now()
}

func (f *testAccess) Validate() error {
	if f.ChildResource != nil && f.ParentResource == nil {
		return macaroon.ErrResourceUnspecified
	}
	return nil
}
