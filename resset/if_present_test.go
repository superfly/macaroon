package resset

import (
	"errors"
	"testing"

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
