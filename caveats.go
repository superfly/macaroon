package macaroon

import (
	"encoding/json"
	"fmt"
	"time"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

// Caveat3P is a requirement that the token be presented along with a 3P discharge token.
type Caveat3P struct {
	Location    string
	VerifierKey []byte // used by the initial issuer to verify discharge macaroon
	Ticket      []byte // used by the 3p service to construct discharge macaroon

	// HMAC key for 3P caveat
	rn []byte `msgpack:"-"`
}

func NewCaveat3P(ka EncryptionKey, loc string, cs ...Caveat) (*Caveat3P, error) {
	if len(ka) != EncryptionKeySize {
		return nil, fmt.Errorf("bad key size: have %d, need %d", len(ka), EncryptionKeySize)
	}

	// make a new root hmac key for the 3p discharge macaroon
	rn := NewSigningKey()

	// make the ticket, which is consumed by the 3p service; then
	// encode and encrypt it
	ticket := &wireTicket{
		DischargeKey: rn,
		Caveats:      *NewCaveatSet(cs...),
	}

	ticketBytes, err := encode(ticket)
	if err != nil {
		return nil, fmt.Errorf("encoding ticket: %w", err)
	}

	return &Caveat3P{
		Location: loc,
		Ticket:   seal(ka, ticketBytes),
		rn:       rn,
	}, nil
}

func init()                                { RegisterCaveatType(&Caveat3P{}) }
func (c *Caveat3P) CaveatType() CaveatType { return Cav3P }
func (c *Caveat3P) Name() string           { return "3P" }

func (c *Caveat3P) Prohibits(f Access) error {
	// Caveat3P are part of token verification and  have no role in
	// access validation.
	return fmt.Errorf("%w (3rd party caveat)", ErrBadCaveat)
}

// ValidityWindow establishes the window of time the token is valid for.
type ValidityWindow struct {
	NotBefore int64 `json:"not_before"`
	NotAfter  int64 `json:"not_after"`
}

func init()                                      { RegisterCaveatType(&ValidityWindow{}) }
func (c *ValidityWindow) CaveatType() CaveatType { return CavValidityWindow }
func (c *ValidityWindow) Name() string           { return "ValidityWindow" }

func (c *ValidityWindow) Prohibits(f Access) error {
	na := time.Unix(c.NotAfter, 0)
	if f.Now().After(na) {
		return fmt.Errorf("%w: token only valid until %s", ErrUnauthorized, na)
	}

	nb := time.Unix(c.NotBefore, 0)
	if f.Now().Before(nb) {
		return fmt.Errorf("%w: token not valid until %s", ErrUnauthorized, nb)
	}

	return nil
}

// BindToParentToken is used by discharge tokens to state that they may only
// be used to discharge 3P caveats for a specific root token or further
// attenuated versions of that token. This prevents a discharge token from
// being used with less attenuated versions of the specified token, effectively
// binding the discharge token to the root token. This caveat may appear
// multiple times to iteratively clamp down which versions of the root token
// the discharge token may be used with.
//
// The parent token is identified by a prefix of the SHA256 digest of the
// token's signature.
type BindToParentToken []byte

func init()                                         { RegisterCaveatType(&BindToParentToken{}) }
func (c *BindToParentToken) CaveatType() CaveatType { return CavBindToParentToken }
func (c *BindToParentToken) Name() string           { return "BindToParentToken" }

func (c *BindToParentToken) Prohibits(f Access) error {
	// BindToParentToken are part of token verification and  have no role in
	// access validation.
	return fmt.Errorf("%w (bind-to-parent)", ErrBadCaveat)
}

type UnregisteredCaveat struct {
	Type       CaveatType
	Body       any
	RawJSON    []byte
	RawMsgpack []byte
}

func (c *UnregisteredCaveat) CaveatType() CaveatType { return c.Type }
func (c *UnregisteredCaveat) Name() string           { return "Unregistered" }

func (c *UnregisteredCaveat) Prohibits(f Access) error {
	return fmt.Errorf("%w (unregistered)", ErrBadCaveat)
}

func (c UnregisteredCaveat) MarshalMsgpack() ([]byte, error) {
	// JSON is just for user-readability, but msgpack is what's used for
	// signature verification. With struct tags, etc, it's lossy to encode
	// things from json<->msgpack, so we just don't allow it.
	if len(c.RawMsgpack) == 0 {
		return nil, fmt.Errorf("cannot convert unregistered caveats from JSON to msgpack")
	}
	return c.RawMsgpack, nil
}

func (c *UnregisteredCaveat) UnmarshalMsgpack(data []byte) error {
	c.RawMsgpack = data
	return msgpack.Unmarshal(data, &c.Body)
}

func (c UnregisteredCaveat) MarshalJSON() ([]byte, error) {
	// JSON is just for user-readability, but msgpack is what's used for
	// signature verification. With struct tags, etc, it's lossy to encode
	// things from json<->msgpack, so we just don't allow it.
	if len(c.RawJSON) == 0 {
		return nil, fmt.Errorf("cannot convert unregistered caveats from msgpack to JSON")
	}
	return c.RawJSON, nil
}

func (c *UnregisteredCaveat) UnmarshalJSON(data []byte) error {
	c.RawJSON = data
	return json.Unmarshal(data, &c.Body)
}
