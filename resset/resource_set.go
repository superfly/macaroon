package resset

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
	msgpack "github.com/vmihailenco/msgpack/v5"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type Integer interface {
	uint | uint8 | uint16 | uint32 | uint64 | int | int8 | int16 | int32 | int64
}

// ZeroID gets the zero value (0, or "") for a resource. This is used to refer
// to an unspecified resource. For example, when creating a new app, you would
// check for app:0:c permission.
func ZeroID[ID Integer | string]() (ret ID) {
	return
}

// ResourceSet is a helper type for defining caveat types specifying
// object->permission mappings. ResourceSets implement custom msgpack
// marshalling. As a result, they should be wrapped in a struct rather than
// simply aliasing the type. For example, don't do this:
//
//	type myCaveat resset.ResourceSet[uint64]
//
// Instead, do this:
//
//	type myCaveat struct {
//	  Resources resset.ResourceSet[uint64]
//	}
type ResourceSet[ID Integer | string | Prefix] map[ID]Action

func New[ID Integer | string | Prefix](p Action, ids ...ID) ResourceSet[ID] {
	ret := make(ResourceSet[ID], len(ids))

	for _, id := range ids {
		ret[id] = p
	}

	return ret
}

func (rs ResourceSet[ID]) Prohibits(id *ID, action Action) error {
	if err := rs.validate(); err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("%w resource", ErrResourceUnspecified)
	}

	var (
		foundPerm = false
		perm      = ActionAll
		zeroID    ID
	)

	if zeroPerm, hasZero := rs[zeroID]; hasZero {
		perm &= zeroPerm
		foundPerm = true
	}

	for entryID, entryPerm := range rs {
		if match(entryID, *id) {
			perm &= entryPerm
			foundPerm = true
		}
	}

	if !foundPerm {
		return fmt.Errorf("%w %v", ErrUnauthorizedForResource, *id)
	}

	if !action.IsSubsetOf(perm) {
		return fmt.Errorf("%w access %s (%s not allowed)", ErrUnauthorizedForAction, action, action.Remove(perm))
	}

	return nil
}

var _ msgpack.CustomEncoder = ResourceSet[uint64]{}
var _ msgpack.CustomEncoder = ResourceSet[int32]{}
var _ msgpack.CustomEncoder = ResourceSet[string]{}

func (rs ResourceSet[ID]) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeMapLen(len(rs)); err != nil {
		return err
	}

	// map ordering is random and we need canonical encoding
	ids := maps.Keys(rs)
	slices.Sort(ids)

	for _, id := range ids {
		if err := enc.Encode(id); err != nil {
			return err
		}

		if err := enc.Encode(rs[id]); err != nil {
			return err
		}
	}

	return nil
}

func (rs ResourceSet[ID]) validate() error {
	var zeroID ID
	if _, hasZero := rs[zeroID]; hasZero && len(rs) != 1 {
		return fmt.Errorf("%w: cannot specify zero ID along with other IDs", macaroon.ErrBadCaveat)
	}
	return nil
}

func match[ID Integer | string | Prefix](a, b ID) bool {
	m, isM := any(a).(matcher[ID])
	return a == b || (isM && m.Match(b))
}

type matcher[T any] interface {
	Match(T) bool
}

type Prefix string

var _ matcher[Prefix] = Prefix("")

func (p Prefix) Match(other Prefix) bool {
	return strings.HasPrefix(string(other), string(p))
}
