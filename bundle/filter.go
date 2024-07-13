package bundle

import "github.com/superfly/macaroon"

// Filter filters a slice of Toks. It can be passed to [Bundle.Select] or
// [ParseBundleWithFilter].
type Filter interface {
	// Apply does the work of filtering Toks. It is expected that the filter
	// modifies the slice that is passed in, but doesn't change the order of
	// elements.
	Apply([]Token) []Token
}

type filterFunc func([]Token) []Token

func (f filterFunc) Apply(ts []Token) []Token {
	return f(ts)
}

// DefaultFilter rejects invalid macaroons and discharge tokens that aren't
// associated with any permission token.
func DefaultFilter(permissionLocation string) Filter {
	return filterFunc(func(ts []Token) []Token {
		ts = NotInvalidMacaroon.Apply(ts)

		_, permsByDis, _, _ := tokens(ts).dischargeMaps(permissionLocation)
		notExtraneous := Predicate(func(t Token) bool { return len(permsByDis[t.(*MacaroonToken)]) > 0 })

		return Or(
			NotMacaroon,
			IsLocation(permissionLocation),
			notExtraneous,
		).Apply(ts)
	})
}

func isMissingDischarge(permissionLocation, tpLocation string) Filter {
	isPerm := IsLocation(permissionLocation)

	return filterFunc(func(ts []Token) []Token {
		_, _, dissByTicket, _ := tokens(ts).dischargeMaps(permissionLocation)

		pred := Predicate(func(t Token) bool {
			if !isPerm(t) {
				return false
			}

			for _, ticket := range t.(*MacaroonToken).UnsafeMacaroon.TicketsForThirdParty(tpLocation) {
				if len(dissByTicket[string(ticket)]) == 0 {
					return true
				}
			}

			return false
		})

		return pred.Apply(ts)
	})
}

func withDischarges(permissionLocation string, f Filter) Filter {
	return filterFunc(func(ts []Token) []Token {
		fMap := tokens(ts).Select(f).existenceMap()
		_, permByDis, _, _ := tokens(ts).dischargeMaps(permissionLocation)

		pred := Predicate(func(t Token) bool {
			switch {
			case fMap[t]:
				return true
			case !IsValidMacaroon(t):
				return false
			}

			for _, p := range permByDis[t.(*MacaroonToken)] {
				if fMap[p] {
					return true
				}
			}

			return false
		})

		return pred.Apply(ts)
	})
}

// Predicate is a type of Filter that returns a yes/no answer for each Token.
type Predicate func(Token) bool

// IsLocation returns a Predicate that checking for macaroons with a given
// location.
func IsLocation(loc string) Predicate {
	return func(t Token) bool {
		return IsValidMacaroon(t) && t.(*MacaroonToken).UnsafeMacaroon.Location == loc
	}
}

func HasCaveat[C macaroon.Caveat](t Token) bool {
	if !IsValidMacaroon(t) {
		return false
	}

	cavs := macaroon.GetCaveats[C](&t.(*MacaroonToken).UnsafeMacaroon.UnsafeCaveats)
	return len(cavs) != 0
}

// And returns a Predicate requiring all of ps to be true.
func And(ps ...Predicate) Predicate {
	return func(t Token) bool {
		for _, p := range ps {
			if !p(t) {
				return false
			}
		}

		return true
	}
}

// Or returns a Predicate requiring one of ps to be true.
func Or(ps ...Predicate) Predicate {
	return func(t Token) bool {
		for _, p := range ps {
			if p(t) {
				return true
			}
		}

		return false
	}
}

// Not returns a Predicate requiring the opposite of p.
func Not(p Predicate) Predicate {
	return func(t Token) bool {
		return !p(t)
	}
}

// Apply implements Filter.
func (p Predicate) Apply(ts []Token) []Token {
	ret := ts[:0]

	for _, t := range ts {
		if p(t) {
			ret = append(ret, t)
		}
	}

	// clear remainder of original slice so GC can reclaim memory
	for i := len(ret); i < len(ts); i++ {
		ts[i] = nil
	}

	return ret
}

func isType[T Token](t Token) bool {
	_, ok := t.(T)
	return ok
}

var (
	KeepAll            = Predicate(func(Token) bool { return true })
	KeepNone           = Predicate(func(Token) bool { return false })
	IsMacaroon         = Predicate(isType[*MacaroonToken])
	NotMacaroon        = Not(IsMacaroon)
	IsValidMacaroon    = Predicate(func(t Token) bool { return IsMacaroon(t) && t.(*MacaroonToken).Error == nil })
	NotInvalidMacaroon = Or(NotMacaroon, IsValidMacaroon)
	IsVerifiedMacaroon = Predicate(func(t Token) bool { return IsValidMacaroon(t) && t.(*MacaroonToken).VerifiedCaveats != nil })
)
