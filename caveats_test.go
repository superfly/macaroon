package macaroon

import (
	"errors"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestSimple(t *testing.T) {
	hk := NewSigningKey()

	m1, err := New([]byte("foo"), "bar", hk)
	assert.NoError(t, err)

	m1.Add(cavParent(ActionAll, 1010))

	no := func(fs []Access) {
		t.Helper()
		cavs, err := m1.Verify(hk, nil, nil)
		assert.NoError(t, err)
		assert.Error(t, cavs.Validate(fs...))
	}

	yes := func(fs []Access) {
		t.Helper()
		cavs, err := m1.Verify(hk, nil, nil)
		assert.NoError(t, err)
		assert.NoError(t, cavs.Validate(fs...))
	}

	yes([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionWrite,
		},
	})

	m1.Add(cavParent(ActionRead, 1010))

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionWrite,
		},
	})

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionWrite,
		},
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
		},
	})

	yes([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(666)),
		},
	})

	m1.Add(cavChild(ActionAll, 666))

	yes([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(666)),
		},
	})

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(667)),
		},
	})

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionWrite,
			childResource:  ptr(uint64(666)),
		},
	})

	m1, err = New([]byte("foo"), "bar", hk)
	assert.NoError(t, err)

	m1.Add(cavParent(ActionAll, 1010))
	m1.Add(cavChild(ActionAll, 666))
	m1.Add(cavChild(ActionRead, 666))

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionWrite,
			childResource:  ptr(uint64(666)),
		},
	})

	yes([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(666)),
		},
	})

	m1.Add(cavExpiry(5 * time.Minute))

	yes([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(666)),
			now:            time.Now().Add(1 * time.Minute),
		},
	})

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(666)),
			now:            time.Now().Add(100 * time.Minute),
		},
	})

	no([]Access{
		&testAccess{
			parentResource: ptr(uint64(1010)),
			action:         ActionRead,
			childResource:  ptr(uint64(666)),
			now:            time.Now().Add(-(100 * time.Minute)),
		},
	})
}

func TestIfPresent(t *testing.T) {
	var (
		cavs []Caveat
	)

	no := func(expected error, f Access) {
		t.Helper()
		err := NewCaveatSet(cavs...).Validate(f)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, expected))
	}

	yes := func(f Access) {
		t.Helper()
		assert.NoError(t, NewCaveatSet(cavs...).Validate(f))
	}

	cavs = []Caveat{
		cavParent(ActionRead|ActionWrite|ActionCreate|ActionDelete, 123),
		&IfPresent{
			Ifs:  NewCaveatSet(cavChild(ActionRead|ActionDelete|ActionControl, 234)),
			Else: ActionRead | ActionCreate,
		},
	}

	// failing before IfPresent
	no(ErrResourceUnspecified, &testAccess{childResource: ptr(uint64(234)), action: ActionRead})                                       // no parent
	no(ErrUnauthorizedForResource, &testAccess{parentResource: ptr(uint64(987)), childResource: ptr(uint64(234)), action: ActionRead}) // bad parent

	// hit if block (success)
	yes(&testAccess{parentResource: ptr(uint64(123)), childResource: ptr(uint64(234)), action: ActionRead})

	// hit if block (failure)
	no(ErrUnauthorizedForResource, &testAccess{parentResource: ptr(uint64(123)), childResource: ptr(uint64(876)), action: ActionRead})  // wrong child
	no(ErrUnauthorizedForAction, &testAccess{parentResource: ptr(uint64(123)), childResource: ptr(uint64(234)), action: ActionWrite})   // action disallowed by child caveat
	no(ErrUnauthorizedForAction, &testAccess{parentResource: ptr(uint64(123)), childResource: ptr(uint64(234)), action: ActionControl}) // action disallowed by parent caveat

	// hit else block (success)
	yes(&testAccess{parentResource: ptr(uint64(123)), action: ActionRead | ActionCreate})

	// hit else block (failure)
	no(ErrUnauthorizedForAction, &testAccess{parentResource: ptr(uint64(123)), action: ActionWrite})   // action allowed earlier, disallowed by else
	no(ErrUnauthorizedForAction, &testAccess{parentResource: ptr(uint64(123)), action: ActionControl}) // action only allowed by if
}

func ptr[T any](t T) *T {
	return &t
}
