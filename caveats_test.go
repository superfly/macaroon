package macaroon

import (
	"encoding/json"
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

type myUnregistered struct {
	Bar map[string]string `json:"bar"`
	Foo int               `json:"foo"`
}

func (c *myUnregistered) CaveatType() CaveatType   { return cavMyUnregistered }
func (c *myUnregistered) Name() string             { return "MyUnregistered" }
func (c *myUnregistered) Prohibits(f Access) error { return nil }

func TestUnregisteredCaveatJSON(t *testing.T) {
	RegisterCaveatType(&myUnregistered{})
	c := &myUnregistered{Foo: 1, Bar: map[string]string{"a": "b"}}
	cs := NewCaveatSet(c)
	b, err := json.Marshal(cs)
	assert.NoError(t, err)
	unregisterCaveatType(&myUnregistered{})

	cs2 := NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cs2.Caveats))

	uc, ok := cs2.Caveats[0].(*UnregisteredCaveat)
	assert.True(t, ok)
	assert.Equal(t, cavMyUnregistered, uc.Type)

	assert.Equal(t,
		any(map[string]any{
			"bar": map[string]any{
				"a": "b",
			},
			"foo": float64(1),
		}),
		uc.Body,
	)

	_, err = cs2.MarshalMsgpack()
	assert.EqualError(t, err, "cannot convert unregistered caveats from JSON to msgpack")

	b2, err := json.Marshal(cs2)
	assert.NoError(t, err)
	assert.Equal(t, string(b), string(b2))

	RegisterCaveatType(&myUnregistered{})
	t.Cleanup(func() { unregisterCaveatType(&myUnregistered{}) })

	cs3 := NewCaveatSet()
	err = json.Unmarshal(b2, cs3)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs3)
}

func TestUnregisteredCaveatMsgpack(t *testing.T) {
	RegisterCaveatType(&myUnregistered{})
	c := &myUnregistered{Foo: 1, Bar: map[string]string{"a": "b"}}
	cs := NewCaveatSet(c)
	b, err := cs.MarshalMsgpack()
	assert.NoError(t, err)
	unregisterCaveatType(&myUnregistered{})

	cs2, err := DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cs2.Caveats))

	uc, ok := cs2.Caveats[0].(*UnregisteredCaveat)
	assert.True(t, ok)
	assert.Equal(t, cavMyUnregistered, uc.Type)

	assert.Equal(t,
		any([]any{
			map[string]any{
				"a": "b",
			},
			int8(1),
		}),
		uc.Body,
	)

	b2, err := cs2.MarshalMsgpack()
	assert.NoError(t, err)
	assert.Equal(t, b, b2)

	_, err = json.Marshal(cs2)
	assert.EqualError(t, errors.Unwrap(errors.Unwrap(err)), "cannot convert unregistered caveats from msgpack to JSON")

	RegisterCaveatType(&myUnregistered{})
	t.Cleanup(func() { unregisterCaveatType(&myUnregistered{}) })

	cs3, err := DecodeCaveats(b2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cs3.Caveats))
	mucs := GetCaveats[*myUnregistered](cs3)
	assert.Equal(t, 1, len(mucs))
	assert.Equal(t, c, mucs[0])
}

func ptr[T any](t T) *T {
	return &t
}
