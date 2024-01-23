package macaroon

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestCaveatRegistry(t *testing.T) {
	var (
		c  Caveat = &testCaveatParentResource{ID: 123, Permission: ActionRead}
		j1        = []byte(`[{"type":"ParentResource", "body":{"ID": 123, "Permission": 1}}]`)
		j2        = []byte(`[{"type":"Foobar", "body":{"ID": 123, "Permission": 1}}]`)
		cs        = new(CaveatSet)
	)

	assert.NoError(t, json.Unmarshal(j1, cs))
	assert.Equal(t, 1, len(cs.Caveats))
	assert.Equal(t, c, cs.Caveats[0])

	RegisterCaveatJSONAlias(cavTestParentResource, "Foobar")
	t.Cleanup(func() { unegisterCaveatJSONAlias("Foobar") })

	assert.NoError(t, json.Unmarshal(j1, cs))
	assert.Equal(t, 1, len(cs.Caveats))
	assert.Equal(t, c, cs.Caveats[0])

	assert.NoError(t, json.Unmarshal(j2, cs))
	assert.Equal(t, 1, len(cs.Caveats))
	assert.Equal(t, c, cs.Caveats[0])
}
