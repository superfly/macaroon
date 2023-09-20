package resset

import "github.com/superfly/macaroon"

// Access describes an Action being taken on a resource. Must be implemented to
// use IfPresent caveats.
type Access interface {
	macaroon.Access
	GetAction() macaroon.Action
}
