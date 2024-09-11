package resset

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
	msgpack "github.com/vmihailenco/msgpack/v5"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type ID interface {
	constraints.Integer | ~string
}

type BitMask interface {
	constraints.Unsigned
	String() string
}

// IsSubsetOf returns wether all bits in a are set in b.
func IsSubsetOf[M BitMask](a, b M) bool {
	return a&b == a
}

// Remove returns the bits in a but not b
func Remove[M BitMask](a, b M) M {
	return (a & b) ^ a
}

// ZeroID gets the zero value (0, or "") for a resource. This is used to refer
// to an unspecified resource. For example, when creating a new app, you would
// check for app:0:c permission.
func ZeroID[I ID]() (ret I) {
	return
}

// ResourceSet is a helper type for defining caveat types specifying
// object->permission mappings. ResourceSets implement custom msgpack
// marshalling. As a result, they should be wrapped in a struct rather than
// simply aliasing the type. For example, don't do this:
//
//	type myCaveat resset.ResourceSet[uint64, Action]
//
// Instead, do this:
//
//	type myCaveat struct {
//	  Resources resset.ResourceSet[uint64, Action]
//	}
type ResourceSet[I ID, M BitMask] map[I]M

func New[I ID, M BitMask](m M, ids ...I) ResourceSet[I, M] {
	ret := make(ResourceSet[I, M], len(ids))

	for _, id := range ids {
		ret[id] = m
	}

	return ret
}

func (rs ResourceSet[I, M]) Prohibits(id *I, action M, resourceType string) error {
	if err := rs.validate(); err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("%w %s", ErrResourceUnspecified, resourceType)
	}

	var (
		foundPerm  = false
		zeroID     I
		zeroM      M
		maxM       = zeroM - 1
		perm       = maxM
		allowedIDs []I
	)

	if zeroPerm, hasZero := rs[zeroID]; hasZero {
		perm &= zeroPerm
		foundPerm = true
		allowedIDs = append(allowedIDs, zeroID)
	}

	for entryID, entryPerm := range rs {
		allowedIDs = append(allowedIDs, entryID)

		if match(entryID, *id) {
			perm &= entryPerm
			foundPerm = true
		}
	}

	if !foundPerm {
		return fmt.Errorf("%w %s %v (only %v)", ErrUnauthorizedForResource, resourceType, *id, allowedIDs)
	}

	if !IsSubsetOf(action, perm) {
		return fmt.Errorf("%w access %s on %s (%s not allowed)", ErrUnauthorizedForAction, action, resourceType, Remove(action, perm))
	}

	return nil
}

var _ msgpack.CustomEncoder = ResourceSet[uint64, Action]{}
var _ msgpack.CustomEncoder = ResourceSet[int32, Action]{}
var _ msgpack.CustomEncoder = ResourceSet[string, Action]{}

func (rs ResourceSet[I, M]) EncodeMsgpack(enc *msgpack.Encoder) error {
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

func (rs ResourceSet[ID, M]) validate() error {
	var zeroID ID
	if _, hasZero := rs[zeroID]; hasZero && len(rs) != 1 {
		return fmt.Errorf("%w: cannot specify zero ID along with other IDs", macaroon.ErrBadCaveat)
	}
	return nil
}

func match[I ID](a, b I) bool {
	m, isM := any(a).(matcher[I])
	return a == b || (isM && m.Match(b))
}

type matcher[I any] interface {
	Match(I) bool
}

type Prefix string

var _ matcher[Prefix] = Prefix("")

func (p Prefix) Match(other Prefix) bool {
	return strings.HasPrefix(string(other), string(p))
}
