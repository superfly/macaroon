package macaroon

import (
	"errors"
	"fmt"
)

var (
	ErrUnrecognizedToken = errors.New("bad token")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrInvalidAccess     = fmt.Errorf("%w: bad data for token verification", ErrUnauthorized)
	ErrBadCaveat         = fmt.Errorf("%w: bad caveat", ErrUnauthorized)
)
