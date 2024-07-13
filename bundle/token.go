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
			ts = append(ts, NonMacaroonToken(part))
			continue
		}
		if pfx != permissionTokenLabel && pfx != dischargeTokenLabel && pfx != v2TokenLabel {
			ts = append(ts, NonMacaroonToken(part))
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			ts = append(ts, &MacaroonToken{
				Str:   part,
				Error: fmt.Errorf("%w: bad base64: %w", macaroon.ErrUnrecognizedToken, err),
			})

			continue
		}

		mac, err := macaroon.Decode(raw)
		if err != nil {
			ts = append(ts, &MacaroonToken{
				Str:   part,
				Error: fmt.Errorf("bad macaroon: %w", err),
			})

			continue
		}

		ts = append(ts, &MacaroonToken{
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
		if IsMacaroon(t) {
			merr = errors.Join(merr, t.(*MacaroonToken).Error)
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

func (ts tokens) Verify(permissionLoc string, key macaroon.SigningKey, trusted3Ps map[string][]macaroon.EncryptionKey) {
	var dms []*macaroon.Macaroon

	isPerm := IsLocation(permissionLoc)
	dissByPerm, _, _, _ := ts.dischargeMaps(permissionLoc)

	for _, t := range ts {
		if !isPerm(t) {
			continue
		}

		mt := t.(*MacaroonToken)

		dms = dms[:0]
		for _, d := range dissByPerm[mt] {
			dms = append(dms, d.UnsafeMacaroon)
		}

		mt.VerifiedCaveats, mt.Error = mt.UnsafeMacaroon.VerifyParsed(key, dms, trusted3Ps)
	}
}

func (ts tokens) Validate(accesses ...macaroon.Access) error {
	merr := errors.New("no authorized tokens")

	for _, t := range ts {
		if !IsVerifiedMacaroon(t) {
			continue
		}

		mt := t.(*MacaroonToken)

		if err := mt.VerifiedCaveats.Validate(accesses...); err != nil {
			merr = errors.Join(merr, fmt.Errorf("token %s: %w", mt.UnsafeMacaroon.Nonce.UUID(), err))
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

// TicketCaveatValidator is a callback for validating caveats extracted from a
// third-party ticket. These caveats are a restriction placed by the 1p on under
// what conditions the 3p should issue a discharge. If there are caveats and the
// 3p doesn't know how to deal with them, it should return an error. If the 3p
// is willing to discharge the ticket, it should return the set of caveats to
// add to the discharge macaroon.
type TicketCaveatValidator func([]macaroon.Caveat) ([]macaroon.Caveat, error)

func (ts *tokens) Discharge(permissionLocation, tpLocation string, tpKey macaroon.EncryptionKey, cb TicketCaveatValidator) error {
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

			dmt := &MacaroonToken{
				Str:            dmStr,
				UnsafeMacaroon: dm,
			}

			newDiss = append(newDiss, dmt)
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
		mt  *MacaroonToken
		m   *macaroon.Macaroon
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
			mt   = t.(*MacaroonToken)
			uuid = mt.UnsafeMacaroon.Nonce.UUID()
			r    = replacement{mt: mt}
			err  error
		)

		r.m, err = mt.UnsafeMacaroon.Clone()
		if err != nil {
			merr = errors.Join(merr, fmt.Errorf("clone token %s: %w", uuid, err))
			continue
		}

		cavsBefore := r.m.UnsafeCaveats.Caveats
		if err = r.m.Add(caveats...); err != nil {
			merr = errors.Join(merr, fmt.Errorf("attenuate token %s: %w", uuid, err))
			continue
		}

		if mt.VerifiedCaveats != nil {
			r.vcs, err = mt.VerifiedCaveats.Clone()
			if err != nil {
				merr = errors.Join(merr, fmt.Errorf("clone verified caveats %s: %w", uuid, err))
				continue
			}

			// m.Add() might skip duplicate caveats, so we figure out for
			// ourselves which ones were added and put them in the
			// VerifiedCaveats field.
			added := r.m.UnsafeCaveats.Caveats[len(cavsBefore):]
			r.vcs.Caveats = append(r.vcs.Caveats, added...)
		}

		if r.str, err = r.m.String(); err != nil {
			merr = errors.Join(merr, fmt.Errorf("encode token %s: %w", uuid, err))
			continue
		}

		replacements = append(replacements, &r)
	}

	if merr != nil {
		return merr
	}

	for _, r := range replacements {
		r.mt.Str = r.str
		r.mt.UnsafeMacaroon = r.m
		r.mt.VerifiedCaveats = r.vcs
	}

	return nil

}

// dischargesByPermission returns
//   - a map of permission tokens to their discharge tokens
//   - a map of discharge tokens to their permission tokens
//   - a map of tickets to their discharge tokens
//   - a map of undischarged tickets by 3p location.
func (ts tokens) dischargeMaps(permissionLocation string) (dbp map[*MacaroonToken][]*MacaroonToken, pbd map[*MacaroonToken][]*MacaroonToken, dbt map[string][]*MacaroonToken, ubl map[string][][]byte) {
	isPerm := IsLocation(permissionLocation)

	// size is a guess
	dbt = make(map[string][]*MacaroonToken, len(ts)/2)

	var (
		nPerm = 0
		nDiss = 0
	)

	for _, t := range ts {
		switch {
		case !IsValidMacaroon(t):
			continue
		case isPerm(t):
			nPerm++
			continue
		}

		nDiss++

		mt := t.(*MacaroonToken)
		skid := string(mt.UnsafeMacaroon.Nonce.KID)
		dbt[skid] = append(dbt[skid], mt)
	}

	dbp = make(map[*MacaroonToken][]*MacaroonToken, nPerm)
	pbd = make(map[*MacaroonToken][]*MacaroonToken, nDiss)
	ubl = make(map[string][][]byte)

	for _, t := range ts {
		if !isPerm(t) {
			continue
		}

		mt := t.(*MacaroonToken)

		for tLoc, tickets := range mt.UnsafeMacaroon.ThirdPartyTickets() {
			for _, ticket := range tickets {
				diss := dbt[string(ticket)]
				if len(diss) == 0 {
					ubl[tLoc] = append(ubl[tLoc], ticket)
				} else {
					dbp[mt] = append(dbp[mt], diss...)

					for _, d := range diss {
						pbd[d] = append(pbd[d], mt)
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

type MacaroonToken struct {
	Str             string
	Error           error
	VerifiedCaveats *macaroon.CaveatSet

	// UnsafeMacaroon is the macaroon.Macaroon that was parsed from Str. It is
	// not safe to modify (e.g. attenuate) this Macaroon directly, since updates
	// need to be written to other fields in this struct. It is also not safe to
	// use this Macaroon outside of a Select() call on a Bundle if concurrent
	// callers might be accessing the Bundle or its tokens.
	UnsafeMacaroon *macaroon.Macaroon
}

var _ Token = (*MacaroonToken)(nil)

// implement Token
func (t *MacaroonToken) String() string { return t.Str }

type NonMacaroonToken string

var _ Token = NonMacaroonToken("")

func (t NonMacaroonToken) String() string { return string(t) }
