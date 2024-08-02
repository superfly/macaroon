package flyio

import (
	"fmt"

	"github.com/superfly/macaroon"
)

var (
	ErrUnauthorizedForRole = fmt.Errorf("%w for role", macaroon.ErrUnauthorized)
)
