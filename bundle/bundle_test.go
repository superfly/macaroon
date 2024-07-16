package bundle

import (
	"testing"

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

var (
	permLoc = "perm-loc"
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
