package resset

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
	"github.com/vmihailenco/msgpack/v5"
)

func TestResourceSet(t *testing.T) {
	zero := ZeroID[string]()
	rs := &ResourceSet[string, Action]{
		"foo": ActionRead | ActionWrite,
		"bar": ActionWrite,
	}

	assert.NoError(t, rs.Prohibits(ptr("foo"), ActionRead|ActionWrite))
	assert.NoError(t, rs.Prohibits(ptr("bar"), ActionWrite))
	assert.True(t, errors.Is(rs.Prohibits(nil, ActionWrite), ErrResourceUnspecified))
	assert.True(t, errors.Is(rs.Prohibits(ptr("baz"), ActionWrite), ErrUnauthorizedForResource))
	assert.True(t, errors.Is(rs.Prohibits(ptr(zero), ActionWrite), ErrUnauthorizedForResource))
	assert.True(t, errors.Is(rs.Prohibits(ptr("foo"), ActionAll), ErrUnauthorizedForAction))
}

func TestZeroID(t *testing.T) {
	zero := ZeroID[string]()
	rs := &ResourceSet[string, Action]{zero: ActionRead}

	assert.NoError(t, rs.Prohibits(ptr("foo"), ActionRead))
	assert.NoError(t, rs.Prohibits(ptr(zero), ActionRead))

	assert.True(t, errors.Is(rs.Prohibits(nil, ActionRead), ErrResourceUnspecified))
	assert.True(t, errors.Is(rs.Prohibits(ptr("foo"), ActionWrite), ErrUnauthorizedForAction))
	assert.True(t, errors.Is(rs.Prohibits(ptr(zero), ActionWrite), ErrUnauthorizedForAction))

	rs = &ResourceSet[string, Action]{
		zero:  ActionRead | ActionWrite,
		"bar": ActionWrite,
	}
	assert.True(t, errors.Is(rs.validate(), macaroon.ErrBadCaveat))
}

func TestResourceSetJSON(t *testing.T) {
	rs := New[uint64](ActionRead, 3, 1, 2)

	rsj, err := json.Marshal(rs)
	assert.NoError(t, err)

	// json sorts map keys so this is reliable
	rsj2, err := json.Marshal(map[string]string{"1": "r", "2": "r", "3": "r"})
	assert.NoError(t, err)
	assert.Equal(t, rsj2, rsj)

	rs2 := ResourceSet[uint64, Action]{}
	assert.NoError(t, json.Unmarshal(rsj, &rs2))
	assert.Equal(t, rs, rs2)
}

func TestResourceSetMessagePack(t *testing.T) {
	rs := New[uint64](ActionRead, 3, 1, 2)

	rsm, err := encode(rs)
	assert.NoError(t, err)

	rs2 := ResourceSet[uint64, Action]{}
	assert.NoError(t, msgpack.Unmarshal(rsm, &rs2))
	assert.Equal(t, rs, rs2)

	rsm2buf := &bytes.Buffer{}
	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)
	enc.Reset(rsm2buf)
	enc.UseCompactInts(true)

	assert.NoError(t, enc.EncodeMapLen(3))
	assert.NoError(t, enc.Encode(1))
	assert.NoError(t, enc.Encode(ActionRead))
	assert.NoError(t, enc.Encode(2))
	assert.NoError(t, enc.Encode(ActionRead))
	assert.NoError(t, enc.Encode(3))
	assert.NoError(t, enc.Encode(ActionRead))
	assert.Equal(t, rsm2buf.Bytes(), rsm)

	rsm3, err := encode(map[uint64]Action{1: ActionRead, 2: ActionRead, 3: ActionRead})
	assert.NoError(t, err)

	rs3 := ResourceSet[uint64, Action]{}
	assert.NoError(t, msgpack.Unmarshal(rsm3, &rs3))
	assert.Equal(t, rs, rs3)
}

func encode(v interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}

	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)

	enc.Reset(buf)
	enc.UseArrayEncodedStructs(true)
	enc.UseCompactInts(true)

	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
