package resource_set

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
	msgpack "github.com/vmihailenco/msgpack/v5"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// ZeroID gets the zero value (0, or "") for a resource. This is used to refer
// to an unspecified resource. For example, when creating a new app, you would
// check for app:0:c permission.
func ZeroID[ID uint64 | string]() (ret ID) {
	return
}

// ResourceSet is a helper type for defining caveat types specifying
// object->permission mappings.
type ResourceSet[ID uint64 | string | Prefix] map[ID]macaroon.Action

func New[ID uint64 | string | Prefix](p macaroon.Action, ids ...ID) ResourceSet[ID] {
	ret := make(ResourceSet[ID], len(ids))

	for _, id := range ids {
		ret[id] = p
	}

	return ret
}

func (rs ResourceSet[ID]) Prohibits(id *ID, action macaroon.Action) error {
	if err := rs.validate(); err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("%w resource", macaroon.ErrResourceUnspecified)
	}

	var (
		foundPerm = false
		perm      = macaroon.ActionAll
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
		return fmt.Errorf("%w %v", macaroon.ErrUnauthorizedForResource, *id)
	}

	if !action.IsSubsetOf(perm) {
		return fmt.Errorf("%w access %s (%s not allowed)", macaroon.ErrUnauthorizedForAction, action, action.Remove(perm))
	}

	return nil
}

var _ msgpack.CustomEncoder = ResourceSet[uint64]{}
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

func match[ID uint64 | string | Prefix](a, b ID) bool {
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
