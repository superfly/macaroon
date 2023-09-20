package macaroon

import (
	"time"
)

// Access represents the user's attempt to access some resource. Different
// caveats will require different contextual information.
type Access interface {
	// The current time
	Now() time.Time

	// Callback for validating the structure
	Validate() error
}
