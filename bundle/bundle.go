package bundle

import (
	"context"
	"sync"

	"github.com/superfly/macaroon"
)

const (
	flyV1Scheme          = "FlyV1"
	bearerScheme         = "Bearer"
	permissionTokenLabel = "fm1r"
	dischargeTokenLabel  = "fm1a"
	v2TokenLabel         = "fm2"
	tokDelim             = ","
	pfxDelim             = "_"
)

// Bundle is a collection of tokens parsed from an Authorization header. It is
// safe for concurrent use.
type Bundle struct {
	IsPermissionToken Predicate
	m                 *sync.RWMutex
	ts                tokens
}

// ParseBundle is the same as ParseBundleWithFilter, but uses the DefaultFilter.
func ParseBundle(permissionLocation, hdr string) (*Bundle, error) {
	f := DefaultFilter(LocationFilter(permissionLocation).Predicate())

	return ParseBundleWithFilter(permissionLocation, hdr, f)
}

// ParseBundleWithFilter parses a FlyV1 Authorization header into a Bundle. The
// Bundle is usable regardless of whether an error is returned. The provided
// filter is applied to the parsed tokens. The returned error is constructed
// before the tokens are filtered and will contain information about invalid
// tokens that may be filtered.
func ParseBundleWithFilter(permissionLocation, hdr string, filter Filter) (*Bundle, error) {
	var (
		ts  = parseToks(hdr)
		err = ts.Error()
	)

	b := &Bundle{
		IsPermissionToken: LocationFilter(permissionLocation).Predicate(),
		m:                 new(sync.RWMutex),
		ts:                filter.Apply(ts),
	}

	return b, err
}

// AddTokens parses the provided header and adds the tokens to the Bundle. If an
// error occurs during parsing, the Bundle remains unchanged.
func (b *Bundle) AddTokens(hdr string) error {
	ts := parseToks(hdr)

	if err := ts.Error(); err != nil {
		return err
	}

	b.m.Lock()
	defer b.m.Unlock()

	b.ts = append(b.ts, ts...)

	return nil
}

// Select returns a new Bundle containing only the tokens matching the filter. The
// underlying Tokens are the same.
func (b *Bundle) Select(f Filter) *Bundle {
	b.m.RLock()
	defer b.m.RUnlock()

	return &Bundle{
		IsPermissionToken: b.IsPermissionToken,
		m:                 b.m,
		ts:                b.ts.Select(f),
	}
}

// Filter modifies the Bundle in place, removing tokens that don't match the
// provided Filter.
func (b *Bundle) Filter(f Filter) {
	b.m.Lock()
	defer b.m.Unlock()

	b.ts = f.Apply(b.ts)
}

// IsMissingDischarge returns a Filter that selects only permission tokens that
// are missing discharges for the specified 3p location.
func (b *Bundle) IsMissingDischarge(tpLocation string) Filter {
	return isMissingDischarge(b.IsPermissionToken, tpLocation)
}

// WithDischarges returns a Filter selecting tokens matching f and their discharges.
func (b *Bundle) WithDischarges(f Filter) Filter {
	return withDischarges(b.IsPermissionToken, f)
}

// Header returns the Authorization header value for the Bundle.
func (b *Bundle) Header() string {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.Header()
}

// String returns the string representation of the Bundle.
func (b *Bundle) String() string {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.String()
}

// Error returns the combined errors from all macaroons in the Bundle. These
// errors are populated during initial parsing as well as during [Verify].
func (b *Bundle) Error() error {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.Error()
}

// Len returns the number of tokens in the Bundle.
func (b *Bundle) Len() int {
	b.m.RLock()
	defer b.m.RUnlock()

	return len(b.ts)
}

// IsEmpty returns true if the Bundle contains no tokens.
func (b *Bundle) IsEmpty() bool {
	b.m.RLock()
	defer b.m.RUnlock()

	return len(b.ts) == 0
}

// Any returns true if any of the tokens in the Bundle match the filter.
func (b *Bundle) Any(f Filter) bool {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.Count(f) > 0
}

// Count returns the number of tokens in the Bundle that match the filter.
func (b *Bundle) Count(f Filter) int {
	// avoid copying the slice if the filter is a Predicate
	if pred, ok := f.(Predicate); ok {
		return Reduce(b, func(count int, t Token) int {
			if pred(t) {
				return count + 1
			}

			return count
		})
	}

	return len(b.ts.Select(f))
}

// Verify attempts to verify the signature of every macaroon in the Bundle.
// Successfully verified macaroons will be the subject for future [Validate]
// calls. Unsuccessfully verified tokens will be annotated with their
// error, which can be checked with the Error method.
func (b *Bundle) Verify(ctx context.Context, v Verifier) ([]*macaroon.CaveatSet, error) {
	b.m.Lock()
	defer b.m.Unlock()

	return b.ts.Verify(ctx, b.IsPermissionToken, v)
}

// Validate attempts to validate the provided accesses against all verified
// macaroons in the Bundle. If no macaroon satisfies all the accesses, the
// combination of errors from all failed macaroons is returned.
func (b *Bundle) Validate(accesses ...macaroon.Access) error {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.Validate(accesses...)
}

// UndischargedThirdPartyTickets returns a map of third-party locations to their
// third party tickets that we don't have a discharge for.
func (b *Bundle) UndischargedThirdPartyTickets() map[string][][]byte {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.undischargedTicketsByLocation(b.IsPermissionToken)
}

// UndischargedTicketsForThirdParty returns a list of tickets for the specified
// third party that we don't have a discharge for.
func (b *Bundle) UndischargedTicketsForThirdParty(tpLocation string) [][]byte {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.UndischargedThirdPartyTickets()[tpLocation]
}

// Discharger is a callback for validating caveats extracted from a third-party
// ticket. These caveats are a restriction placed by the 1p on under what
// conditions the 3p should issue a discharge. If there are caveats and the 3p
// doesn't know how to deal with them, it should return an error. If the 3p is
// willing to discharge the ticket, it should return the set of caveats to add
// to the discharge macaroon.
type Discharger func([]macaroon.Caveat) ([]macaroon.Caveat, error)

// Discharge attempts to discharge any third-party caveats for tpLocation. The
// provided callback (cb) is invoked to validate any caveats in tickets and to
// provide discharge macaroons.
func (b *Bundle) Discharge(tpLocation string, tpKey macaroon.EncryptionKey, cb Discharger) error {
	b.m.Lock()
	defer b.m.Unlock()

	return b.ts.Discharge(b.IsPermissionToken, tpLocation, tpKey, cb)
}

// Attenuate adds caveats to the permission macaroons in the Bundle. If any part
// of this fails, the bundle remains unchanged.
func (b *Bundle) Attenuate(caveats ...macaroon.Caveat) error {
	b.m.Lock()
	defer b.m.Unlock()

	return b.ts.Attenuate(b.IsPermissionToken, caveats...)
}

// Clone returns a deep copy of the Bundle by serializing and re-parsing it.
func (b *Bundle) Clone() *Bundle {
	b.m.RLock()
	defer b.m.RUnlock()

	return &Bundle{
		IsPermissionToken: b.IsPermissionToken,
		m:                 new(sync.RWMutex),
		ts:                parseToks(b.Header()),
	}
}

// ForEach calls the provided callback for each token in the Bundle.
func ForEach[T Token](b *Bundle, cb func(T)) {
	b.m.RLock()
	defer b.m.RUnlock()

	for _, t := range b.ts {
		if tt, ok := t.(T); ok {
			cb(tt)
		}
	}
}

// Map applies the callback to each token in the Bundle and returns a slice of
// the callback's return values.
func Map[R any, T Token](b *Bundle, cb func(T) R) []R {
	b.m.RLock()
	defer b.m.RUnlock()

	var ret []R
	for _, t := range b.ts {
		if tt, ok := t.(T); ok {
			ret = append(ret, cb(tt))
		}
	}

	return ret
}

// Reduce applies the callback to each token in the Bundle, accumulating the
// result.
func Reduce[A any, T Token](b *Bundle, cb func(A, T) A) A {
	b.m.RLock()
	defer b.m.RUnlock()

	var acc A
	for _, t := range b.ts {
		if tt, ok := t.(T); ok {
			acc = cb(acc, tt)
		}
	}

	return acc
}
