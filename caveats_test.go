package macaroon

import (
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

func ptr[T any](t T) *T {
	return &t
}
