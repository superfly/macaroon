package storage

import (
	"fmt"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

const (
	CavObjects = macaroon.CavStorageObjects
)

// Objects limits what objects can be accessed. Objects are identified by a URL
// prefix string, so you can specify just the storage provider (e.g.
// `https://storage.fly/`), a specific bucket within a storage provider (e.g.
// `https://storage.fly/my_bucket`), or a object within a bucket (e.g.
// `https://storage.fly/my_bucket/my_file`).
type Objects struct {
	Prefixes resset.ResourceSet[resset.Prefix] `json:"objects"`
}

// RestrictObjects returns a caveat limiting what objects can be accessed.
func RestrictObjects(action resset.Action, prefixes ...resset.Prefix) *Objects {
	return &Objects{Prefixes: resset.New(action, prefixes...)}
}

func init() {
	macaroon.RegisterCaveatType(&Objects{})
}

func (c *Objects) CaveatType() macaroon.CaveatType { return CavObjects }
func (c *Objects) Name() string                    { return "Objects" }

func (c *Objects) Prohibits(a macaroon.Access) error {
	sa, isAccess := a.(*Access)
	if !isAccess {
		return fmt.Errorf("%w: access isn't storage.Access", macaroon.ErrInvalidAccess)
	}

	return c.Prefixes.Prohibits(&sa.Object, sa.Action)
}
