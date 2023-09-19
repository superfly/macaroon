package flyio

import "github.com/superfly/macaroon"

const (
	// well-known locations
	LocationPermission     = "https://api.fly.io/v1"
	LocationAuthentication = "https://api.fly.io/aaa/v1"
	LocationSecrets        = "https://api.fly.io/secrets/v1"
)

// ParseRootAndDischargeTokens takes a string header and parses out the fly.io
// permission and discharge tokens.
func ParsePermissionAndDischargeTokens(header string) ([]byte, [][]byte, error) {
	return macaroon.ParsePermissionAndDischargeTokens(header, LocationPermission)
}
