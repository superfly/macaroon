package flyio

import "github.com/superfly/macaroon/bundle"

var (
	IsPermissionToken = bundle.IsLocation(LocationPermission)
	IsAuthToken       = bundle.IsLocation(LocationAuthentication)
	IsNewAuthToken    = bundle.IsLocation(LocationNewAuthentication)
	IsSecretsToken    = bundle.IsLocation(LocationSecrets)
)

func IsForOrg(oid uint64) bundle.Predicate {
	return bundle.Predicate(func(t bundle.Token) bool {
		if !IsPermissionToken(t) {
			return false
		}

		os, err := OrganizationScope(&t.(*bundle.MacaroonToken).UnsafeMacaroon.UnsafeCaveats)
		return err == nil && os == oid
	})
}

func ParseBundle(hdr string) (*bundle.Bundle, error) {
	return bundle.ParseBundle(LocationPermission, hdr)
}

func ParseBundleWithFilter(hdr string, filter bundle.Filter) (*bundle.Bundle, error) {
	return bundle.ParseBundleWithFilter(LocationPermission, hdr, filter)
}
