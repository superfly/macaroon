package bundle

import (
	"errors"
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
	m        *sync.RWMutex
	permLoc  string
	ts       tokens
	filtered bool
}

// ParseBundle is the same as ParseBundleWithFilter, but uses the DefaultFilter.
func ParseBundle(permissionLocation, hdr string) (*Bundle, error) {
	return ParseBundleWithFilter(permissionLocation, hdr, DefaultFilter(permissionLocation))
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
		m:       new(sync.RWMutex),
		permLoc: permissionLocation,
		ts:      filter.Apply(ts),
	}

	return b, err
}

// PermissionTokenNonces returns the nonces of all permission tokens in the
// Bundle.
func (b *Bundle) PermissionTokenNonces() []macaroon.Nonce {
	b.m.RLock()
	defer b.m.RUnlock()

	var (
		isPerm = b.IsPermission()
		ret    = make([]macaroon.Nonce, 0, len(b.ts)/2)
	)

	for _, t := range b.ts {
		if isPerm(t) {
			ret = append(ret, t.(Macaroon).Nonce())
		}
	}

	return ret
}

// AddTokens is the same as AddTokensWithFilter, but uses the DefaultFilter.
func (b *Bundle) AddTokens(hdr string) error {
	return b.AddTokensWithFilter(hdr, DefaultFilter(b.permLoc))
}

// AddTokensWithFilter parses the provided header and adds the tokens to the
// Bundle after applying the provided filter. The returned error is constructed
// before the tokens are filtered and will contain information about invalid
// tokens that may be filtered.
func (b *Bundle) AddTokensWithFilter(hdr string, filter Filter) error {
	var (
		ts  = parseToks(hdr)
		err = ts.Error()
	)

	b.m.Lock()
	defer b.m.Unlock()

	b.ts = filter.Apply(append(b.ts, ts...))

	return err
}

// Select returns a new Bundle containing only the tokens matching the filter. The
// underlying Tokens are the same.
//
// New tokens (e.g. [Discharge]) cannot be added to a Bundle returned by Select.
func (b *Bundle) Select(f Filter) *Bundle {
	b.m.RLock()
	defer b.m.RUnlock()

	return &Bundle{
		m:        b.m,
		permLoc:  b.permLoc,
		ts:       b.ts.Select(f),
		filtered: true,
	}
}

// IsMissingDischarge returns a Filter that selects only permission tokens that
// are missing discharges for the specified 3p location.
func (b *Bundle) IsMissingDischarge(tpLocation string) Filter {
	return isMissingDischarge(b.permLoc, tpLocation)
}

// WithDischarges returns a Filter selecting tokens matching f and their discharges.
func (b *Bundle) WithDischarges(f Filter) Filter {
	return withDischarges(b.permLoc, f)
}

// IsPermission returns a Predicate checking whether a token is a permission
// macaroon.
func (b *Bundle) IsPermission() Predicate {
	return IsLocation(b.permLoc)
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

// N returns the number of tokens in the Bundle.
func (b *Bundle) N() int {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.N()
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

	return !b.ts.Select(f).IsEmpty()
}

// Count returns the number of tokens in the Bundle that match the filter.
func (b *Bundle) Count(f Filter) int {
	return b.ts.Select(f).N()
}

// Verify attempts to verify the signature of every macaroon in the Bundle.
// Successfully verified macaroons will be the subject for future [Validate]
// calls. Unsuccessfully verified tokens will be annotated with their
// error, which can be checked with the Error method.
func (b *Bundle) Verify(v Verifier) error {
	b.m.Lock()
	defer b.m.Unlock()

	return b.ts.Verify(b.permLoc, v)
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

	return b.ts.UndischargedThirdPartyTickets(b.permLoc)
}

// UndischargedTicketsForThirdParty returns a list of tickets for the specified
// third party that we don't have a discharge for.
func (b *Bundle) UndischargedTicketsForThirdParty(tpLocation string) [][]byte {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.UndischargedTicketsForThirdParty(b.permLoc, tpLocation)
}

// Discharge attempts to discharge any third-party caveats for tpLocation. The
// provided callback (cb) is invoked to validate any caveats in tickets and to
// provide discharge macaroons.
func (b *Bundle) Discharge(tpLocation string, tpKey macaroon.EncryptionKey, cb Discharger) error {
	b.m.Lock()
	defer b.m.Unlock()

	if b.filtered {
		return errors.New("cannot discharge a bundle returned by Select")
	}

	return b.ts.Discharge(b.permLoc, tpLocation, tpKey, cb)
}

// Attenuate adds caveats to the permission macaroons in the Bundle. If any part
// of this fails, the bundle remains unchanged.
func (b *Bundle) Attenuate(caveats ...macaroon.Caveat) error {
	b.m.Lock()
	defer b.m.Unlock()

	return b.ts.Attenuate(b.permLoc, caveats...)
}

// UnsafeMacaroons returns the macaroons from the Bundle. These are not safe to
// access/modify if another goroutine might be using the Bundle. Modifications
// to the Bundle might result in changes in the returned Macaroons.
func (b *Bundle) UnsafeMacaroons() []*macaroon.Macaroon {
	b.m.RLock()
	defer b.m.RUnlock()

	return b.ts.UnsafeMacaroons()
}

// Clone returns a deep copy of the Bundle by serializing and re-parsing it.
func (b *Bundle) Clone() *Bundle {
	b.m.RLock()
	defer b.m.RUnlock()

	bb, _ := ParseBundleWithFilter(b.permLoc, b.Header(), KeepAll)

	return bb
}
