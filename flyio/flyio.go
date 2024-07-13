package flyio

import (
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/tp"
)

const (
	// well-known locations
	LocationPermission        = "https://api.fly.io/v1"
	LocationAuthentication    = "https://api.fly.io/aaa/v1"
	LocationNewAuthentication = "https://auth.fly.io"
	LocationSecrets           = "https://api.fly.io/secrets/v1"
)

// ParseRootAndDischargeTokens takes a string header and parses out the fly.io
// permission and discharge tokens.
func ParsePermissionAndDischargeTokens(header string) ([]byte, [][]byte, error) {
	return macaroon.ParsePermissionAndDischargeTokens(header, LocationPermission)
}

// DischargeClient returns a *tp.Client suitable for discharging third party
// caveats in fly.io permission tokens.
func DischargeClient(opts ...tp.ClientOption) *tp.Client {
	return tp.NewClient(LocationPermission, opts...)
}
