package bundle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
)

func TestParseBundle(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		b, err := ParseBundle(permLoc, "")
		assert.NoError(t, err)
		assert.Equal(t, "", b.String())
	})

	t.Run("preserves order", func(t *testing.T) {
		t.Parallel()

		const orig = "d,e,f,a,b,c"
		b, err := ParseBundle(permLoc, orig)
		assert.NoError(t, err)
		assert.Equal(t, orig, b.String())
	})

	t.Run("filters", func(t *testing.T) {
		t.Parallel()

		const (
			orig     = "d,e,f,a,b,c"
			filtered = "d,e,a,b,c"
		)

		b, err := ParseBundleWithFilter(permLoc, orig, Predicate(func(t Token) bool {
			return t.String() != "f"
		}))
		assert.NoError(t, err)
		assert.Equal(t, filtered, b.String())
	})

	t.Run("keeps non-macaroons with prefix", func(t *testing.T) {
		const (
			orig = "fo1_xxx"
		)

		b, err := ParseBundle(permLoc, orig)
		assert.NoError(t, err)
		assert.Equal(t, orig, b.String())
	})

	t.Run("captures macaroon errors", func(t *testing.T) {
		t.Parallel()

		const (
			orig     = "d,e,fm2_f,a,b,c"
			filtered = "d,e,a,b,c"
		)

		b, err := ParseBundle(permLoc, orig)
		assert.Error(t, err)
		assert.Equal(t, filtered, b.String())
	})

	t.Run("filters extraneous discharges", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
		extra := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
		withExtra := append(toks, extra[1])

		b, err := ParseBundle(permLoc, withExtra.String())
		assert.NoError(t, err)
		assert.Equal(t, toks.String(), b.String())
	})

	t.Run("filters permission tokens from other locs", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
		extra := macOpts{loc: "bad-loc"}.tokens(t)
		withExtra := append(toks, extra[0])

		b, err := ParseBundle(permLoc, withExtra.String())
		assert.NoError(t, err)
		assert.Equal(t, toks.String(), b.String())
	})
}

func TestAddTokens(t *testing.T) {
	t.Parallel()

	t.Run("unchanged if error", func(t *testing.T) {
		t.Parallel()

		t1 := macOpts{}.tokens(t)
		t2 := macOpts{}.tokens(t)

		b, err := ParseBundle(permLoc, t1.String())
		assert.NoError(t, err)
		assert.Error(t, b.AddTokens(t2.String()+",fm2_xxx"))
		assert.Equal(t, t1.String(), b.String())
	})

	t.Run("adds tokens", func(t *testing.T) {
		t.Parallel()

		t1 := macOpts{}.tokens(t)
		t2 := macOpts{}.tokens(t)

		b, err := ParseBundle(permLoc, t1.String())
		assert.NoError(t, err)
		assert.NoError(t, b.AddTokens(t2.String()))
		assert.Equal(t, append(t1, t2...).String(), b.String())
	})
}

func TestSelect(t *testing.T) {
	t.Parallel()

	const (
		orig     = "a,b,c"
		filtered = "a,c"
	)

	var notB Predicate = func(t Token) bool {
		return t.String() != "b"
	}

	b, err := ParseBundle(permLoc, orig)
	assert.NoError(t, err)

	t.Run("doesn't modify bundle", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, filtered, b.Select(notB).String())
		assert.Equal(t, orig, b.String())
	})

	t.Run("clears out extra capacity", func(t *testing.T) {
		ts := b.Select(notB).ts
		assert.Equal(t, 3, cap(ts))
		assert.Zero(t, ts[:3][2])
	})
}

func TestIsMissingDischarge(t *testing.T) {
	t.Parallel()

	t.Run("no discharges", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{}}}.tokens(t)
		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		assert.Equal(t, 1, bun.Count(bun.IsMissingDischarge(tpLoc)))
		assert.Equal(t, 0, bun.Count(bun.IsMissingDischarge("bogus")))
	})

	t.Run("no tp caveat", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{}.tokens(t)
		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		assert.Equal(t, 0, bun.Count(bun.IsMissingDischarge(tpLoc)))
		assert.Equal(t, 0, bun.Count(bun.IsMissingDischarge("bogus")))
	})

	t.Run("with discharge", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		assert.Equal(t, 0, bun.Count(bun.IsMissingDischarge(tpLoc)))
		assert.Equal(t, 0, bun.Count(bun.IsMissingDischarge("bogus")))
	})

}

func TestWithDischarges(t *testing.T) {
	t.Parallel()

	t.Run("no discharges", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{}}}.tokens(t)

		perm := toks[0]
		isPerm := Predicate(func(t Token) bool {
			return t.String() == perm.String()
		})

		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		assert.Equal(t, perm.String(), bun.Select(bun.WithDischarges(isPerm)).String())
		assert.Equal(t, "", bun.Select(bun.WithDischarges(KeepNone)).String())
	})

	t.Run("no tp caveat", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{}.tokens(t)

		perm := toks[0]
		isPerm := Predicate(func(t Token) bool {
			return t.String() == perm.String()
		})

		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		assert.Equal(t, perm.String(), bun.Select(bun.WithDischarges(isPerm)).String())
		assert.Equal(t, "", bun.Select(bun.WithDischarges(KeepNone)).String())
	})

	t.Run("with discharge", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)

		perm := toks[0]
		isPerm := Predicate(func(t Token) bool {
			return t.String() == perm.String()
		})

		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		assert.Equal(t, toks.String(), bun.Select(bun.WithDischarges(isPerm)).String())
		assert.Equal(t, "", bun.Select(bun.WithDischarges(KeepNone)).String())
	})

	t.Run("with extra discharge", func(t *testing.T) {
		t.Parallel()

		toks := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
		extra := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
		withExtra := append(toks, extra[1])

		perm := toks[0]
		isPerm := Predicate(func(t Token) bool {
			return t.String() == perm.String()
		})

		bun, err := ParseBundleWithFilter(permLoc, withExtra.String(), KeepAll)
		assert.NoError(t, err)

		assert.Equal(t, toks.String(), bun.Select(bun.WithDischarges(isPerm)).String())
		assert.Equal(t, "", bun.Select(bun.WithDischarges(KeepNone)).String())
	})
}

type verifierFunc func(ctx context.Context, dischargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult

func (vf verifierFunc) Verify(ctx context.Context, dischargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
	return vf(ctx, dischargesByPermission)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	t1 := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
	t2 := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
	extra := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
	toks := append(append(t1, t2...), extra[1])

	t.Run("calls verifier with discharges by perm", func(t *testing.T) {
		t.Parallel()

		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		_, err = bun.Verify(context.Background(), verifierFunc(func(ctx context.Context, dischargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
			ret := make(map[Macaroon]VerificationResult, len(dischargesByPermission))
			assert.Equal(t, 2, len(dischargesByPermission))

			for perm, diss := range dischargesByPermission {
				assert.Equal(t, 1, len(diss))
				var expectedDis Token

				switch perm.String() {
				case t1[0].String():
					expectedDis = t1[1]
				case t2[0].String():
					expectedDis = t2[1]
				default:
					t.Fatal("unexpected permission")
				}

				assert.Equal(t, expectedDis.String(), diss[0].String())
				ret[perm] = &VerifiedMacaroon{perm.Unverified(), perm.UnsafeCaveats()}
			}

			return ret
		}))
		assert.NoError(t, err)
	})

	t.Run("returns error if none verified", func(t *testing.T) {
		t.Parallel()

		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		_, err = bun.Verify(context.Background(), verifierFunc(func(ctx context.Context, dischargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
			ret := make(map[Macaroon]VerificationResult, len(dischargesByPermission))
			for perm := range dischargesByPermission {
				ret[perm] = &FailedMacaroon{perm.Unverified(), errors.New("hi")}
			}
			return ret
		}))

		assert.Contains(t, err.Error(), "no verified tokens")

		failed := bun.Select(Predicate(isType[*FailedMacaroon]))
		assert.Equal(t, 2, failed.Len())
		assert.EqualError(t, failed.ts[:1].Error(), "hi")
		assert.EqualError(t, failed.ts[1:].Error(), "hi")
	})

	t.Run("returns ok if any verified", func(t *testing.T) {
		t.Parallel()

		bun, err := ParseBundle(permLoc, toks.String())
		assert.NoError(t, err)

		_, err = bun.Verify(context.Background(), verifierFunc(func(ctx context.Context, dischargesByPermission map[Macaroon][]Macaroon) map[Macaroon]VerificationResult {
			ret := make(map[Macaroon]VerificationResult, len(dischargesByPermission))

			for perm := range dischargesByPermission {
				switch perm.String() {
				case t1[0].String():
					ret[perm] = &VerifiedMacaroon{perm.Unverified(), perm.UnsafeCaveats()}
				case t2[0].String():
					ret[perm] = &FailedMacaroon{perm.Unverified(), errors.New("hi")}
				default:
					t.Fatal("unexpected permission")
				}
			}

			return ret
		}))

		assert.NoError(t, err)
		assert.Equal(t, 1, bun.Count(Predicate(isType[*VerifiedMacaroon])))

		failed := bun.Select(Predicate(isType[*FailedMacaroon]))
		assert.Equal(t, 1, failed.Len())
		assert.EqualError(t, failed.Error(), "hi")
	})
}

func TestUndischargedThirdPartyTickets(t *testing.T) {
	t.Parallel()

	t1 := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
	t2 := macOpts{tpOpts: []tpOpt{{loc: "undischarged"}}}.tokens(t)
	toks := append(t1, t2...)

	bun, err := ParseBundle(permLoc, toks.String())
	assert.NoError(t, err)

	utpts := bun.UndischargedThirdPartyTickets()
	assert.Equal(t, 1, len(utpts))
	assert.NotZero(t, utpts["undischarged"])
}

func TestDischarge(t *testing.T) {
	t.Parallel()

	cav1 := macaroon.Caveat(&macaroon.ValidityWindow{NotBefore: 1, NotAfter: time.Now().Add(time.Hour).Unix()})
	cav2 := macaroon.Caveat(&macaroon.ValidityWindow{NotBefore: 2, NotAfter: time.Now().Add(time.Hour).Unix()})

	toks := macOpts{tpOpts: []tpOpt{{tcavs: []macaroon.Caveat{cav1}}}}.tokens(t)
	bun, err := ParseBundle(permLoc, toks.String())
	assert.NoError(t, err)

	err = bun.Discharge(tpLoc, tpKey, func(cavs []macaroon.Caveat) ([]macaroon.Caveat, error) {
		assert.True(t, cavsHasCaveat(cavs, cav1))
		return []macaroon.Caveat{cav2}, nil
	})
	assert.NoError(t, err)

	vcavs, err := bun.Verify(context.Background(), WithKey(permKID, permKey, nil))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(vcavs))
	assert.True(t, cavsHasCaveat(vcavs[0].Caveats, cav2))
}

func TestAttenuate(t *testing.T) {
	t.Parallel()

	toks := macOpts{tpOpts: []tpOpt{{discharge: true}}}.tokens(t)
	_, err := toks.Verify(context.Background(), isPerm, WithKey(permKID, permKey, nil))
	assert.NoError(t, err)
	toks = append(toks, macOpts{}.tokens(t)...)

	cav := &macaroon.ValidityWindow{NotBefore: 1, NotAfter: 2}
	assert.NoError(t, toks.Attenuate(isPerm, cav))

	hasCav := hasCaveat(cav)

	assert.True(t, hasCav(toks[0]))
	assert.False(t, hasCav(toks[1]))
	assert.True(t, hasCav(toks[2]))
}

func hasCaveat(c macaroon.Caveat) Predicate {
	return MacaroonPredicate(func(m Macaroon) bool {
		if !cavsHasCaveat(m.UnsafeCaveats().Caveats, c) {
			return false
		}

		if vm, ok := m.(*VerifiedMacaroon); ok {
			return cavsHasCaveat(vm.Caveats.Caveats, c)
		}

		return true
	})
}

func cavsHasCaveat(cavs []macaroon.Caveat, caveat macaroon.Caveat) bool {
	for _, c := range cavs {
		if c == caveat || reflect.DeepEqual(c, caveat) {
			return true
		}
	}

	return false

}

var (
	permLoc = "perm-loc"
	isPerm  = LocationFilter(permLoc).Predicate()
	permKID = []byte("perm-kid")
	permKey = macaroon.NewSigningKey()

	tpLoc = "tp-loc"
	tpKey = macaroon.NewEncryptionKey()
)

type macOpts struct {
	loc    string
	kid    []byte
	key    macaroon.SigningKey
	cavs   []macaroon.Caveat
	tpOpts []tpOpt
}

func (mo macOpts) tokens(tb testing.TB) tokens {
	tb.Helper()

	if mo.loc == "" {
		mo.loc = permLoc
	}

	if mo.kid == nil {
		mo.kid = permKID
	}

	if mo.key == nil {
		mo.key = permKey
	}

	mac, err := macaroon.New(mo.kid, mo.loc, mo.key)
	assert.NoError(tb, err)
	assert.NoError(tb, mac.Add(mo.cavs...))

	var diss tokens
	for _, tp := range mo.tpOpts {
		diss = append(diss, tp.add(tb, mac)...)
	}

	macStr, err := mac.String()
	assert.NoError(tb, err)

	return append(tokens{&UnverifiedMacaroon{
		UnsafeMac: mac,
		Str:       macStr,
	}}, diss...)
}

type tpOpt struct {
	loc       string
	key       macaroon.EncryptionKey
	tcavs     []macaroon.Caveat
	discharge bool
	dcavs     []macaroon.Caveat
}

func (to tpOpt) add(tb testing.TB, mac *macaroon.Macaroon) tokens {
	tb.Helper()

	if to.loc == "" {
		to.loc = tpLoc
	}

	if to.key == nil {
		to.key = tpKey
	}

	ticketsBefore := mac.TicketsForThirdParty(to.loc)
	assert.NoError(tb, mac.Add3P(to.key, to.loc, to.tcavs...))

	if !to.discharge {
		return nil
	}

	newTickets := mac.TicketsForThirdParty(to.loc)[len(ticketsBefore):]
	assert.Equal(tb, 1, len(newTickets))

	_, dm, err := macaroon.DischargeTicket(to.key, to.loc, newTickets[0])
	assert.NoError(tb, err)
	assert.NoError(tb, dm.Add(to.dcavs...))

	dmStr, err := dm.String()
	assert.NoError(tb, err)

	return tokens{&UnverifiedMacaroon{
		UnsafeMac: dm,
		Str:       dmStr,
	}}
}
