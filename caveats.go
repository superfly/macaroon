package macaroon

import (
	"fmt"
	"time"
)

// Caveat3P is a requirement that the token be presented along with a 3P discharge token.
type Caveat3P struct {
	Location    string
	VerifierKey []byte // used by the initial issuer to verify discharge macaroon
	Ticket      []byte // used by the 3p service to construct discharge macaroon

	// HMAC key for 3P caveat
	rn []byte `msgpack:"-"`
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
	// IsUser are part of token verification and  have no role in
	// access validation.
	return fmt.Errorf("%w (bind-to-parent)", ErrBadCaveat)
}
