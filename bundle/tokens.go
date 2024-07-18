package bundle

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
)

// tokens does the heavy lifting for Bundle.
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
			ts = append(ts, NonMacaroon(part))
			continue
		}
		if pfx != permissionTokenLabel && pfx != dischargeTokenLabel && pfx != v2TokenLabel {
			ts = append(ts, NonMacaroon(part))
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			ts = append(ts, &MalformedMacaroon{
				Str: part,
				Err: fmt.Errorf("%w: bad base64: %w", macaroon.ErrUnrecognizedToken, err),
			})

			continue
		}

		mac, err := macaroon.Decode(raw)
		if err != nil {
			ts = append(ts, &MalformedMacaroon{
				Str: part,
				Err: fmt.Errorf("bad macaroon: %w", err),
			})

			continue
		}

		ts = append(ts, &UnverifiedMacaroon{
			Str:       part,
			UnsafeMac: mac,
		})
	}

	return ts
}

func (ts tokens) Select(f Filter) tokens {
	return f.Apply(append(tokens(nil), ts...))
}

func (ts tokens) Header() string {
	return Header(ts...)
}

func Header[T Token](ts ...T) string {
	if len(ts) == 0 {
		return ""
	}

	return flyV1Scheme + " " + String(ts...)
}

func (ts tokens) String() string {
	return String(ts...)
}

func String[T Token](ts ...T) string {
	if len(ts) == 0 {
		return ""
	}

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
	type badToken interface {
		Token
		Error() error
	}

	var merr error

	for _, t := range ts {
		if bt, ok := t.(badToken); ok {
			merr = errors.Join(merr, bt.Error())
		}
	}

	return merr
}

func (ts tokens) Verify(ctx context.Context, isPerm Predicate, v Verifier) ([]*macaroon.CaveatSet, error) {
	var (
		verified = make([]*macaroon.CaveatSet, 0, len(ts)/2)
		merr     = errors.New("no verified tokens")
		dbp      = ts.dischargesByPermission(isPerm)
		res      = v.Verify(ctx, dbp)
	)

	if res == nil {
		return nil, merr
	}

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
		case *VerifiedMacaroon:
			verified = append(verified, tt.Caveats)
		case *FailedMacaroon:
			merr = errors.Join(merr,
				fmt.Errorf("token %s: %w", tt.UnsafeMac.Nonce.UUID(), tt.Err),
			)
		default:
			return nil, fmt.Errorf("unexpected verification result: %T", tt)
		}
	}

	if len(verified) == 0 {
		return nil, merr
	}

	return verified, nil
}

func (ts tokens) Validate(accesses ...macaroon.Access) error {
	merr := errors.New("no authorized tokens")

	for _, t := range ts.Select(IsVerifiedMacaroon) {
		vm := t.(*VerifiedMacaroon)

		if err := vm.Caveats.Validate(accesses...); err != nil {
			merr = errors.Join(merr, fmt.Errorf("token %s: %w", vm.UnsafeMac.Nonce.UUID(), err))
		} else {
			return nil
		}
	}

	return merr
}

func (ts *tokens) Discharge(isPerm Predicate, tpLocation string, tpKey macaroon.EncryptionKey, cb Discharger) error {
	var (
		merr    error
		newDiss []Token
		ubl     = ts.undischargedTicketsByLocation(isPerm)
	)

	for tLoc, tickets := range ubl {
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

			dum := &UnverifiedMacaroon{
				Str:       dmStr,
				UnsafeMac: dm,
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

func (ts tokens) Attenuate(isPerm Predicate, caveats ...macaroon.Caveat) error {
	type replacement struct {
		m   Macaroon
		mac *macaroon.Macaroon
		vcs *macaroon.CaveatSet
		str string
	}

	var (
		merr error

		// we stage all our updates in a separate slice, so we can skip applying
		// any changes if there are errors.
		replacements []*replacement
	)

	for _, t := range ts.Select(isPerm) {
		var (
			m     = t.(Macaroon)
			nonce = m.Nonce()
			uuid  = nonce.UUID()
			r     = replacement{m: m}
			err   error
		)

		r.mac, err = m.UnsafeMacaroon().Clone()
		if err != nil {
			merr = errors.Join(merr, fmt.Errorf("clone token %s: %w", uuid, err))
			continue
		}

		cavsBefore := r.mac.UnsafeCaveats.Caveats
		if err = r.mac.Add(caveats...); err != nil {
			merr = errors.Join(merr, fmt.Errorf("attenuate token %s: %w", uuid, err))
			continue
		}

		if vm, ok := t.(*VerifiedMacaroon); ok {
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
		case *UnverifiedMacaroon:
			tt.Str = r.str
			tt.UnsafeMac = r.mac
		case *VerifiedMacaroon:
			tt.Str = r.str
			tt.UnsafeMac = r.mac
			tt.Caveats = r.vcs
		case *FailedMacaroon:
			tt.Str = r.str
			tt.UnsafeMac = r.mac
		default:
			panic(fmt.Sprintf("unexpected token type: %T", tt))
		}
	}

	return nil
}

func (ts tokens) dischargesByPermission(isPerm Predicate) map[Macaroon][]Macaroon {
	var (
		dbt, nPerm, _ = ts.dischargesByTicket(isPerm)
		dbp           = make(map[Macaroon][]Macaroon, nPerm)
	)

	for _, t := range ts.Select(isPerm) {
		m := t.(Macaroon)
		tpts := m.ThirdPartyTickets()
		dbp[m] = make([]Macaroon, 0, len(tpts))

		for _, tickets := range tpts {
			for _, ticket := range tickets {
				dbp[m] = append(dbp[m], dbt[string(ticket)]...)
			}
		}
	}

	return dbp
}

func (ts tokens) permissionsByDischarge(isPerm Predicate) map[Macaroon][]Macaroon {
	var (
		dbt, _, nDiss = ts.dischargesByTicket(isPerm)
		pbd           = make(map[Macaroon][]Macaroon, nDiss)
	)

	for _, t := range ts.Select(isPerm) {
		m := t.(Macaroon)

		for _, tickets := range m.ThirdPartyTickets() {
			for _, ticket := range tickets {
				for _, dis := range dbt[string(ticket)] {
					pbd[dis] = append(pbd[dis], m)
				}
			}
		}
	}

	return pbd
}

func (ts tokens) undischargedTicketsByLocation(isPerm Predicate) map[string][][]byte {
	var (
		dbt, _, _ = ts.dischargesByTicket(isPerm)
		ubl       = make(map[string][][]byte)
	)

	for _, t := range ts.Select(isPerm) {
		m := t.(Macaroon)

		for tLoc, tickets := range m.ThirdPartyTickets() {
			for _, ticket := range tickets {
				if len(dbt[string(ticket)]) == 0 {
					ubl[tLoc] = append(ubl[tLoc], ticket)
				}
			}
		}
	}

	return ubl
}

func (ts tokens) dischargesByTicket(isPerm Predicate) (dbt map[string][]Macaroon, nPerm int, nDiss int) {
	dbt = make(map[string][]Macaroon, len(ts)/2)

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

	return dbt, nPerm, nDiss
}
