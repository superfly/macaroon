package flyio

import "github.com/superfly/macaroon"

// ParseRootAndDischargeTokens takes a string header and parses out the fly.io
// permission and discharge tokens.
func ParsePermissionAndDischargeTokens(header string) ([]byte, [][]byte, error) {
	return macaroon.ParsePermissionAndDischargeTokens(header, macaroon.LocationFlyioPermission)
}
