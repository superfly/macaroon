package resset

import (
	"fmt"

	"github.com/superfly/macaroon"
)

var (
	ErrResourceUnspecified        = fmt.Errorf("%w: must specify", macaroon.ErrInvalidAccess)
	ErrResourcesMutuallyExclusive = fmt.Errorf("%w: resources are mutually exclusive", macaroon.ErrInvalidAccess)
	ErrUnauthorizedForResource    = fmt.Errorf("%w for", macaroon.ErrUnauthorized)
	ErrUnauthorizedForAction      = fmt.Errorf("%w for", macaroon.ErrUnauthorized)
)
