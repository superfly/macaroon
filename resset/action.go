package resset

import (
	"encoding/json"
	"fmt"

	"github.com/superfly/macaroon"
)

// Action is an RWX-style bitmap of actions that can be taken on a resource
// (eg org, app, machine). An Action can describe the permission limitations
// expressed by a caveat or the action a principal is attempting to take on a
// resource. The precise semantics of Actions are left to Caveat/AuthAttempt
// implementations.
type Action uint16

// IsSubsetOf returns wether all bits in p are set in other.
func (a Action) IsSubsetOf(other Action) bool {
	return a&other == a
}

// Remove returns the bits in p but not other
func (a Action) Remove(other Action) Action {
	return (a & other) ^ a
}

const (
	// ActionRead indicates reading attributes of the specified objects.
	ActionRead Action = 1 << iota

	// ActionWrite indicates writing attributes of the specified objects.
	ActionWrite

	// ActionCreate indicates creating the specified object. Since the ID of an
	// object will be unknown before creation, this is mostly meaningless
	// unless inherited from a parent. E.g. org:123:create lets you create
	// app:234 belonging to org:123.
	ActionCreate

	// ActionDelete indicates deleting the specified object.
	ActionDelete

	// ActionControl indicates changing the state of the specified object, but
	// not modifying other attributes. In practice, this mostly applies to
	// starting/stopping/signaling machines.
	ActionControl
)

const (
	ActionAll  = ActionRead | ActionWrite | ActionCreate | ActionDelete | ActionControl
	ActionNone = Action(0)
)

func ActionFromString(ms string) Action {
	var ret Action

	if ms == "*" {
		ret = 0xffff
		return ret
	}

	for _, mc := range ms {
		switch mc {
		case 'r':
			ret |= ActionRead
		case 'w':
			ret |= ActionWrite
		case 'c':
			ret |= ActionCreate
		case 'd':
			ret |= ActionDelete
		case 'C':
			ret |= ActionControl
		}
	}

	return ret
}

func (a Action) String() string {
	str := []byte{}

	if a&ActionRead != 0 {
		str = append(str, 'r')
	}

	if a&ActionWrite != 0 {
		str = append(str, 'w')
	}

	if a&ActionCreate != 0 {
		str = append(str, 'c')
	}

	if a&ActionDelete != 0 {
		str = append(str, 'd')
	}

	if a&ActionControl != 0 {
		str = append(str, 'C')
	}

	return string(str)
}

func (a *Action) UnmarshalJSON(b []byte) error {
	mask := ""

	if err := json.Unmarshal(b, &mask); err != nil {
		return err
	}

	m := ActionFromString(mask)
	*a = m

	return nil
}

func (a Action) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// Implements macaroon.Caveat
func init()                                       { macaroon.RegisterCaveatType(new(Action)) }
func (c *Action) CaveatType() macaroon.CaveatType { return macaroon.CavAction }
func (c *Action) Name() string                    { return "Action" }

// Implements macaroon.Caveat
func (c *Action) Prohibits(a macaroon.Access) error {
	rsa, ok := a.(Access)
	switch {
	case !ok:
		return macaroon.ErrInvalidAccess
	case !rsa.GetAction().IsSubsetOf(*c):
		return fmt.Errorf("%w access %s (%s not allowed)", ErrUnauthorizedForAction, rsa.GetAction(), rsa.GetAction().Remove(*c))
	default:
		return nil
	}
}
