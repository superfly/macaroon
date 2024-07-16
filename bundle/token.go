package bundle

import (
	"time"

	"github.com/superfly/macaroon"
)

type Token interface {
	String() string
}

// BadToken is an FailedMacaroon or MalformedMacaroon.
type BadToken interface {
	Token
	Error() error
}

// Macaroon is a UnverifiedMacaroon, VerifiedMacaroon, or FailedMacaroon.
type Macaroon interface {
	Token

	// Unverified returns the token as an UnverifiedMacaroon.
	Unverified() *UnverifiedMacaroon

	// UnsafeMacaroon returns the parsed macaroon.Macaroon. It is not safe to
	// access this when another goroutine is accessing the Bundle it came from.
	// It is never safe to modify this directly.
	UnsafeMacaroon() *macaroon.Macaroon

	// Location returns the location of this macaroon.
	Location() string

	// Nonce returns the nonce of this macaroon.
	Nonce() macaroon.Nonce

	// UnsafeCaveats returns the unverified caveats from this macaroon.
	UnsafeCaveats() *macaroon.CaveatSet

	// ThirdPartyTickets returns all third party tickets in this macaroon.
	ThirdPartyTickets() map[string][][]byte

	// TicketsForThirdParty returns the tickets for a given third party location.
	TicketsForThirdParty(string) [][]byte
}

// UnverifiedMacaroon is a Macaroon that hasn't been verified yet.
// Discharge tokens are always UnverifiedMacaroons.
type UnverifiedMacaroon struct {
	// Str is the string representation of the token.
	Str string

	// UnsafeMac is the macaroon.Macaroon that was parsed from Str. It is
	// not safe to modify (e.g. attenuate) this Macaroon directly, since updates
	// need to be written to other fields in this struct. It is also not safe to
	// use this Macaroon outside of a Select() call on a Bundle if concurrent
	// callers might be accessing the Bundle or its tokens.
	UnsafeMac *macaroon.Macaroon
}

var (
	_ Token    = (*UnverifiedMacaroon)(nil)
	_ Macaroon = (*UnverifiedMacaroon)(nil)
)

// implement Token
func (t *UnverifiedMacaroon) String() string { return t.Str }

// implement Macaroon
func (t *UnverifiedMacaroon) Unverified() *UnverifiedMacaroon    { return t }
func (t *UnverifiedMacaroon) UnsafeMacaroon() *macaroon.Macaroon { return t.UnsafeMac }
func (t *UnverifiedMacaroon) Location() string                   { return t.UnsafeMac.Location }
func (t *UnverifiedMacaroon) Nonce() macaroon.Nonce              { return t.UnsafeMac.Nonce }

func (t *UnverifiedMacaroon) UnsafeCaveats() *macaroon.CaveatSet {
	return &t.UnsafeMac.UnsafeCaveats
}

func (t *UnverifiedMacaroon) ThirdPartyTickets() map[string][][]byte {
	return t.UnsafeMac.AllThirdPartyTickets()
}

func (t *UnverifiedMacaroon) TicketsForThirdParty(loc string) [][]byte {
	return t.UnsafeMac.TicketsForThirdParty(loc)
}

// VerifiedMacaroon is a Macaroon that passed signature verification.
type VerifiedMacaroon struct {
	*UnverifiedMacaroon

	// Caveats is the set of verified caveats.
	Caveats *macaroon.CaveatSet
}

var (
	_ Token              = (*VerifiedMacaroon)(nil)
	_ Macaroon           = (*VerifiedMacaroon)(nil)
	_ VerificationResult = (*VerifiedMacaroon)(nil)
)

// https://stackoverflow.com/questions/25065055/what-is-the-maximum-time-time-in-go
var maxTime = time.Unix(1<<63-62135596801, 999999999)

// Expiration calculates when this macaroon will expire
func (t *VerifiedMacaroon) Expiration() time.Time {
	ret := maxTime

	for _, vw := range macaroon.GetCaveats[*macaroon.ValidityWindow](t.Caveats) {
		if na := time.Unix(vw.NotAfter, 0); na.Before(ret) {
			ret = na
		}
	}

	return ret
}

// implement VerificationResult
func (t *VerifiedMacaroon) isVerificationResult() {}

// FailedMacaroon is a Macaroon that failed signature verification.
type FailedMacaroon struct {
	*UnverifiedMacaroon

	// Error is the error that occurred while verifying the token.
	Err error
}

var (
	_ Token              = (*FailedMacaroon)(nil)
	_ Macaroon           = (*FailedMacaroon)(nil)
	_ VerificationResult = (*FailedMacaroon)(nil)
)

func (m *FailedMacaroon) Error() error {
	return m.Err
}

// implement VerificationResult
func (t *FailedMacaroon) isVerificationResult() {}

// MalformedMacaroon is a token that looked like a macaroon, but couldn't be parsed.
type MalformedMacaroon struct {
	// Str is the string representation of the token.
	Str string

	// Err is the error that occurred while parsing the token.
	Err error
}

var _ Token = (*MalformedMacaroon)(nil)

func (t *MalformedMacaroon) Error() error { return t.Err }

// implement Token
func (t *MalformedMacaroon) String() string { return t.Str }

// NonMacaroon is a token that doesn't look like a macaroon.
type NonMacaroon string

var _ Token = NonMacaroon("")

func (t NonMacaroon) String() string { return string(t) }
