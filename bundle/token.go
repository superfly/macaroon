package bundle

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
)

// tokens is a non thread-safe version of Bundle. It also doesn't keep track of
// the permission location.
type tokens []Token

func parseToks(hdr string) tokens {
	hdr, _ = macaroon.StripAuthorizationScheme(hdr)

	var (
		parts = strings.Split(hdr, tokDelim)
		n     = len(parts)
		ts    = make(tokens, 0, n)
	)

	for _, part := range parts {
		part = strings.TrimSpace(part)

		pfx, b64, ok := strings.Cut(part, pfxDelim)
		if !ok {
			ts = append(ts, nonMacaroon(part))
			continue
		}
		if pfx != permissionTokenLabel && pfx != dischargeTokenLabel && pfx != v2TokenLabel {
			ts = append(ts, nonMacaroon(part))
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			ts = append(ts, &malformedMacaroon{
				Str:   part,
				Error: fmt.Errorf("%w: bad base64: %w", macaroon.ErrUnrecognizedToken, err),
			})

			continue
		}

		mac, err := macaroon.Decode(raw)
		if err != nil {
			ts = append(ts, &malformedMacaroon{
				Str:   part,
				Error: fmt.Errorf("bad macaroon: %w", err),
			})

			continue
		}

		ts = append(ts, &unverifiedMacaroon{
			Str:            part,
			UnsafeMacaroon: mac,
		})
	}

	return ts
}

func (ts tokens) Select(f Filter) tokens {
	return f.Apply(append(tokens(nil), ts...))
}

func (ts tokens) existenceMap() map[Token]bool {
	m := make(map[Token]bool, len(ts))
	for _, t := range ts {
		m[t] = true
	}
	return m
}

func (ts tokens) Header() string {
	return flyV1Scheme + " " + ts.String()
}

func (ts tokens) String() string {
	var sb strings.Builder

	l := len(ts) - 1
	for _, t := range ts {
		l += len(t.String())
	}
	sb.Grow(l)

	for i, t := range ts {
		if i > 0 {
			sb.WriteString(tokDelim)
		}
		sb.WriteString(t.String())
	}

	return sb.String()
}

func (ts tokens) Error() error {
	var merr error

	for _, t := range ts {
		switch tt := t.(type) {
		case *malformedMacaroon:
			merr = errors.Join(merr, tt.Error)
		case *invalidMacaroon:
			merr = errors.Join(merr, tt.Error)
		}
	}

	return merr

}

func (ts tokens) N() int {
	return len(ts)
}

func (ts tokens) IsEmpty() bool {
	return len(ts) == 0
}

func (ts tokens) Any(f Filter) bool {
	return ts.Select(f).IsEmpty()
}

func (ts tokens) Verify(permLoc string, v Verifier) error {
	var (
		dissByPerm, _, _, _ = ts.dischargeMaps(permLoc)
		res                 = v.Verify(dissByPerm)
		verifiedSome        bool
		merr                = errors.New("no verified tokens")
	)

	for i, t := range ts {
		m, ok := t.(Macaroon)
		if !ok {
			continue
		}

		resT, ok := res[m]
		if !ok {
			continue
		}

		ts[i] = resT

		switch tt := resT.(type) {
		case *verifiedMacaroon:
			verifiedSome = true
		case *invalidMacaroon:
			merr = errors.Join(merr,
				fmt.Errorf("token %s: %w", tt.UnsafeMacaroon.Nonce.UUID(), tt.Error),
			)
		default:
			return fmt.Errorf("unexpected verification result: %T", tt)
		}
	}

	if verifiedSome {
		return nil
	}

	return merr
}

func (ts tokens) Validate(accesses ...macaroon.Access) error {
	merr := errors.New("no authorized tokens")

	for _, t := range ts {
		if !IsVerifiedMacaroon(t) {
			continue
		}

		vm := t.(*verifiedMacaroon)

		if err := vm.Caveats.Validate(accesses...); err != nil {
			merr = errors.Join(merr, fmt.Errorf("token %s: %w", vm.UnsafeMacaroon.Nonce.UUID(), err))
		} else {
			return nil
		}
	}

	return merr
}

func (ts tokens) UndischargedThirdPartyTickets(permissionLocation string) map[string][][]byte {
	_, _, _, undisTicketsByLoc := ts.dischargeMaps(permissionLocation)
	return undisTicketsByLoc
}

func (ts tokens) UndischargedTicketsForThirdParty(permissionLocation string, tpLocation string) [][]byte {
	return ts.UndischargedThirdPartyTickets(permissionLocation)[tpLocation]
}

// Discharger is a callback for validating caveats extracted from a third-party
// ticket. These caveats are a restriction placed by the 1p on under what
// conditions the 3p should issue a discharge. If there are caveats and the 3p
// doesn't know how to deal with them, it should return an error. If the 3p is
// willing to discharge the ticket, it should return the set of caveats to add
// to the discharge macaroon.
type Discharger func([]macaroon.Caveat) ([]macaroon.Caveat, error)

func (ts *tokens) Discharge(permissionLocation, tpLocation string, tpKey macaroon.EncryptionKey, cb Discharger) error {
	var (
		merr                       error
		newDiss                    []Token
		_, _, _, undisTicketsByLoc = ts.dischargeMaps(permissionLocation)
	)

	for tLoc, tickets := range undisTicketsByLoc {
		tpErr := func(err error) error { return fmt.Errorf("location %s: %w", tLoc, err) }

		for _, ticket := range tickets {
			tCavs, dm, err := macaroon.DischargeTicket(tpKey, tpLocation, ticket)
			if err != nil {
				merr = errors.Join(merr, tpErr(err))
				continue
			}

			dmCavs, err := cb(tCavs)
			if err != nil {
				merr = errors.Join(merr, tpErr(err))
				continue
			}

			if err := dm.Add(dmCavs...); err != nil {
				merr = errors.Join(merr, tpErr(err))
				continue
			}

			dmStr, err := dm.String()
			if err != nil {
				merr = errors.Join(merr, tpErr(err))
				continue
			}

			dum := &unverifiedMacaroon{
				Str:            dmStr,
				UnsafeMacaroon: dm,
			}

			newDiss = append(newDiss, dum)
		}
	}

	if merr != nil {
		return merr
	}

	*ts = append(*ts, newDiss...)

	return nil
}

func (ts tokens) Attenuate(permissionLocation string, caveats ...macaroon.Caveat) error {
	type replacement struct {
		m   Macaroon
		mac *macaroon.Macaroon
		vcs *macaroon.CaveatSet
		str string
	}

	var (
		isPerm       = IsLocation(permissionLocation)
		merr         error
		replacements []*replacement
	)

	for _, t := range ts {
		if !isPerm(t) {
			continue
		}

		var (
			m     = t.(Macaroon)
			nonce = m.Nonce()
			uuid  = nonce.UUID()
			r     = replacement{m: m}
			err   error
		)

		r.mac, err = m.getUnsafeMacaroon().Clone()
		if err != nil {
			merr = errors.Join(merr, fmt.Errorf("clone token %s: %w", uuid, err))
			continue
		}

		cavsBefore := r.mac.UnsafeCaveats.Caveats
		if err = r.mac.Add(caveats...); err != nil {
			merr = errors.Join(merr, fmt.Errorf("attenuate token %s: %w", uuid, err))
			continue
		}

		if vm, ok := t.(*verifiedMacaroon); ok {
			r.vcs, err = vm.Caveats.Clone()
			if err != nil {
				merr = errors.Join(merr, fmt.Errorf("clone verified caveats %s: %w", uuid, err))
				continue
			}

			// m.Add() might skip duplicate caveats, so we figure out for
			// ourselves which ones were added and put them in the
			// VerifiedCaveats field.
			added := r.mac.UnsafeCaveats.Caveats[len(cavsBefore):]
			r.vcs.Caveats = append(r.vcs.Caveats, added...)
		}

		if r.str, err = r.mac.String(); err != nil {
			merr = errors.Join(merr, fmt.Errorf("encode token %s: %w", uuid, err))
			continue
		}

		replacements = append(replacements, &r)
	}

	if merr != nil {
		return merr
	}

	for _, r := range replacements {
		switch tt := r.m.(type) {
		case *unverifiedMacaroon:
			tt.Str = r.str
			tt.UnsafeMacaroon = r.mac
		case *verifiedMacaroon:
			tt.Str = r.str
			tt.UnsafeMacaroon = r.mac
			tt.Caveats = r.vcs
		case *invalidMacaroon:
			tt.Str = r.str
			tt.UnsafeMacaroon = r.mac
		}
	}

	return nil
}

func (ts tokens) UnsafeMacaroons() []*macaroon.Macaroon {
	var macs []*macaroon.Macaroon
	for _, t := range ts {
		if m, ok := t.(Macaroon); ok {
			macs = append(macs, m.getUnsafeMacaroon())
		}
	}

	return macs
}

// dischargesByPermission returns
//   - a map of permission tokens to their discharge tokens
//   - a map of discharge tokens to their permission tokens
//   - a map of tickets to their discharge tokens
//   - a map of undischarged tickets by 3p location.
func (ts tokens) dischargeMaps(permissionLocation string) (dbp map[Macaroon][]Macaroon, pbd map[Macaroon][]Macaroon, dbt map[string][]Macaroon, ubl map[string][][]byte) {
	isPerm := IsLocation(permissionLocation)

	// size is a guess
	dbt = make(map[string][]Macaroon, len(ts)/2)

	var (
		nPerm = 0
		nDiss = 0
	)

	for _, t := range ts {
		switch {
		case !IsWellFormedMacaroon(t):
			continue
		case isPerm(t):
			nPerm++
			continue
		}

		nDiss++

		m := t.(Macaroon)
		skid := string(m.Nonce().KID)
		dbt[skid] = append(dbt[skid], m)
	}

	dbp = make(map[Macaroon][]Macaroon, nPerm)
	pbd = make(map[Macaroon][]Macaroon, nDiss)
	ubl = make(map[string][][]byte)

	for _, t := range ts {
		if !isPerm(t) {
			continue
		}

		m := t.(Macaroon)

		for tLoc, tickets := range m.ThirdPartyTickets() {
			for _, ticket := range tickets {
				diss := dbt[string(ticket)]
				if len(diss) == 0 {
					ubl[tLoc] = append(ubl[tLoc], ticket)
				} else {
					dbp[m] = append(dbp[m], diss...)

					for _, d := range diss {
						pbd[d] = append(pbd[d], m)
					}
				}

			}
		}
	}

	return dbp, pbd, dbt, ubl
}

type Token interface {
	String() string
}

type Macaroon interface {
	Token

	getUnverifiedMacaroon() *unverifiedMacaroon
	getUnsafeMacaroon() *macaroon.Macaroon

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

// unverifiedMacaroon is a WellFormedMacaroon that hasn't been verified yet.
type unverifiedMacaroon struct {
	// Str is the string representation of the token.
	Str string

	// UnsafeMacaroon is the macaroon.Macaroon that was parsed from Str. It is
	// not safe to modify (e.g. attenuate) this Macaroon directly, since updates
	// need to be written to other fields in this struct. It is also not safe to
	// use this Macaroon outside of a Select() call on a Bundle if concurrent
	// callers might be accessing the Bundle or its tokens.
	UnsafeMacaroon *macaroon.Macaroon
}

var (
	_ Token    = (*unverifiedMacaroon)(nil)
	_ Macaroon = (*unverifiedMacaroon)(nil)
)

// implement Token
func (t *unverifiedMacaroon) String() string { return t.Str }

// implement WellFormedMacaroon
func (t *unverifiedMacaroon) getUnverifiedMacaroon() *unverifiedMacaroon { return t }
func (t *unverifiedMacaroon) getUnsafeMacaroon() *macaroon.Macaroon      { return t.UnsafeMacaroon }
func (t *unverifiedMacaroon) Location() string                           { return t.UnsafeMacaroon.Location }
func (t *unverifiedMacaroon) Nonce() macaroon.Nonce                      { return t.UnsafeMacaroon.Nonce }

func (t *unverifiedMacaroon) UnsafeCaveats() *macaroon.CaveatSet {
	return &t.UnsafeMacaroon.UnsafeCaveats
}

func (t *unverifiedMacaroon) ThirdPartyTickets() map[string][][]byte {
	return t.UnsafeMacaroon.ThirdPartyTickets()
}

func (t *unverifiedMacaroon) TicketsForThirdParty(loc string) [][]byte {
	return t.UnsafeMacaroon.TicketsForThirdParty(loc)
}

// verifiedMacaroon is a WellFormedMacaroon that passed signature verification.
type verifiedMacaroon struct {
	*unverifiedMacaroon

	// Caveats is the set of verified caveats.
	Caveats *macaroon.CaveatSet
}

// VerifiedMacaroon returns a WellFormedMacaroon annotated with verified caveats.
func VerifiedMacaroon(m Macaroon, cavs *macaroon.CaveatSet) VerificationResult {
	return &verifiedMacaroon{
		unverifiedMacaroon: m.getUnverifiedMacaroon(),
		Caveats:            cavs,
	}
}

var (
	_ Token              = (*verifiedMacaroon)(nil)
	_ Macaroon           = (*verifiedMacaroon)(nil)
	_ VerificationResult = (*verifiedMacaroon)(nil)
)

// implement VerificationResult
func (t *verifiedMacaroon) isVerificationResult() {}

// invalidMacaroon is a WellFormedMacaroon that failed signature verification.
type invalidMacaroon struct {
	*unverifiedMacaroon

	// Error is the error that occurred while verifying the token.
	Error error
}

// InvalidMacaroon returns a WellFormedMacaroon annotated with a verification error.
func InvalidMacaroon(m Macaroon, err error) VerificationResult {
	return &invalidMacaroon{
		unverifiedMacaroon: m.getUnverifiedMacaroon(),
		Error:              err,
	}
}

var (
	_ Token              = (*invalidMacaroon)(nil)
	_ Macaroon           = (*invalidMacaroon)(nil)
	_ VerificationResult = (*invalidMacaroon)(nil)
)

// implement VerificationResult
func (t *invalidMacaroon) isVerificationResult() {}

// malformedMacaroon is a token that looked like a macaroon, but couldn't be parsed.
type malformedMacaroon struct {
	// Str is the string representation of the token.
	Str string

	// Error is the error that occurred while parsing the token.
	Error error
}

var _ Token = (*malformedMacaroon)(nil)

// implement Token
func (t *malformedMacaroon) String() string { return t.Str }

// nonMacaroon is a token that doesn't look like a macaroon.
type nonMacaroon string

var _ Token = nonMacaroon("")

func (t nonMacaroon) String() string { return string(t) }
