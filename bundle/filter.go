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

// DefaultFilter rejects malformed macaroons and discharge tokens that aren't
// associated with any permission token.
func DefaultFilter(isPerm Predicate) Filter {
	return filterFunc(func(ts []Token) []Token {
		pbd := tokens(ts).permissionsByDischarge(isPerm)

		notExtraneous := MacaroonPredicate(func(t Macaroon) bool {
			return len(pbd[t]) > 0
		})

		return Or(
			IsNonMacaroon,
			isPerm,
			notExtraneous,
		).Apply(ts)
	})
}

func isMissingDischarge(isPerm Predicate, tpLocation string) Filter {
	return filterFunc(func(ts []Token) []Token {
		dbt, _, _ := tokens(ts).dischargesByTicket(isPerm)

		pred := And(isPerm, MacaroonPredicate(func(m Macaroon) bool {
			for _, ticket := range m.TicketsForThirdParty(tpLocation) {
				if len(dbt[string(ticket)]) == 0 {
					return true
				}
			}

			return false
		}))

		return pred.Apply(ts)
	})
}

func withDischarges(isPerm Predicate, f Filter) Filter {
	return filterFunc(func(ts []Token) []Token {
		fPred := filterPredicate(f, ts)
		pbd := tokens(ts).permissionsByDischarge(isPerm)

		pred := Or(fPred, MacaroonPredicate(func(t Macaroon) bool {
			for _, p := range pbd[t] {
				if fPred(p) {
					return true
				}
			}

			return false
		}))

		return pred.Apply(ts)
	})
}

func filterPredicate(f Filter, ts tokens) Predicate {
	filtered := tokens(ts).Select(f)
	fMap := make(map[Token]bool, len(filtered))
	for _, t := range filtered {
		fMap[t] = true
	}

	return Predicate(func(t Token) bool {
		return fMap[t]
	})
}

// Predicate is a type of Filter that returns a yes/no answer for each Token.
type Predicate func(Token) bool

// TypedPredicate returns a Predicate for a function operating on a concrete
// Token type.
func TypedPredicate[T Token](p func(T) bool) Predicate {
	return And(isType[T], func(t Token) bool { return p(t.(T)) })
}

// HasCaveat returns a Predicate that selects Tokens with caveats of the given
// type.
func HasCaveat[C macaroon.Caveat](t Token) bool {
	if m, ok := t.(Macaroon); ok {
		return len(macaroon.GetCaveats[C](m.UnsafeCaveats())) != 0
	}

	return false
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

// AllowsAccess returns a Predicate that selects verified macaroons allowing the
// given accesses.
func AllowsAccess(accesses ...macaroon.Access) Predicate {
	return VerifiedMacaroonPredicate(func(vm *VerifiedMacaroon) bool {
		return vm.Caveats.Validate(accesses...) == nil
	})
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
	KeepAll  = Predicate(func(Token) bool { return true })
	KeepNone = Predicate(func(Token) bool { return false })

	IsNonMacaroon        = Predicate(isType[NonMacaroon])
	IsMalformedMacaroon  = Predicate(isType[*MalformedMacaroon])
	IsVerifiedMacaroon   = Predicate(isType[*VerifiedMacaroon])
	IsUnverifiedMacaroon = Predicate(isType[*UnverifiedMacaroon])
	IsFailedMacaroon     = Predicate(isType[*FailedMacaroon])

	IsWellFormedMacaroon = Predicate(isType[Macaroon])
	IsVerificationResult = Predicate(isType[VerificationResult])

	NonMacaroonPredicate        = TypedPredicate[NonMacaroon]
	MalformedMacaroonPredicate  = TypedPredicate[*MalformedMacaroon]
	VerifiedMacaroonPredicate   = TypedPredicate[*VerifiedMacaroon]
	UnverifiedMacaroonPredicate = TypedPredicate[*UnverifiedMacaroon]
	FailedMacaroonPredicate     = TypedPredicate[*FailedMacaroon]
	MacaroonPredicate           = TypedPredicate[Macaroon]
	VerificationResultPredicate = TypedPredicate[VerificationResult]
)

// LocationFilter is a Filter that selects macaroons with the given location.
type LocationFilter string

// Apply implements Filter
func (l LocationFilter) Apply(ts []Token) []Token {
	return l.Predicate().Apply(ts)
}

// Predicate returns a Predicate based on the Filter.
func (l LocationFilter) Predicate() Predicate {
	return MacaroonPredicate(func(m Macaroon) bool {
		return m.Location() == string(l)
	})
}
