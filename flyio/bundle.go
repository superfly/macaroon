package flyio

import (
	"strings"

	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/resset"
)

var (
	IsPermissionToken = bundle.LocationFilter(LocationPermission).Predicate()
	IsAuthToken       = bundle.LocationFilter(LocationAuthentication).Predicate()
	IsNewAuthToken    = bundle.LocationFilter(LocationNewAuthentication).Predicate()
	IsSecretsToken    = bundle.LocationFilter(LocationSecrets).Predicate()
)

// IsForOrgUnverified returns a Predicate, checking that the token is scoped to
// the given organization. Because this operates on unverified tokens, it
// doesn't imply any level of access to the org or that the selected tokens are
// valid.
func IsForOrgUnverified(oid uint64) bundle.Predicate {
	return bundle.MacaroonPredicate(func(t bundle.Macaroon) bool {
		if !IsPermissionToken(t) {
			return false
		}

		os, err := OrganizationScope(t.UnsafeCaveats())
		return err == nil && os == oid
	})
}

// IsForOrg returns a Predicate, checking that the token is scoped to the given
// organization. This doesn't imply any specific level of access to the
// organization.
func IsForOrg(orgID uint64) bundle.Predicate {
	return bundle.AllowsAccess(&Access{
		OrgID:  &orgID,
		Action: resset.ActionNone,
	})
}

func ParseBundle(hdr string) (*bundle.Bundle, error) {
	return bundle.ParseBundle(LocationPermission, hdr)
}

func ParseBundleWithFilter(hdr string, filter bundle.Filter) (*bundle.Bundle, error) {
	return bundle.ParseBundleWithFilter(LocationPermission, hdr, filter)
}

type CSV []string

func (c CSV) String() string {
	return strings.Join(c, ",")
}

// UUIDs returns a CSV of the permission token UUIDs for the given bundle.
func UUIDs(bun *bundle.Bundle) CSV {
	return bundle.Map(bun.Select(IsPermissionToken), func(perm bundle.Macaroon) string {
		return perm.Nonce().UUID().String()
	})
}

// NonceEmails returns a CSV of the permission token pseudo email addresses for
// the given bundle.
func NonceEmails(bun *bundle.Bundle) CSV {
	return bundle.Map(bun.Select(IsPermissionToken), func(perm bundle.Macaroon) string {
		return NonceEmail(perm.Nonce())
	})
}
