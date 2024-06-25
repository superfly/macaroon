package main

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
	macaroon "github.com/superfly/macaroon"
)

func TestCaveatSerialization(t *testing.T) {
	b, err := json.Marshal(caveats)
	assert.NoError(t, err)

	cs2 := macaroon.NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, caveats, cs2)

	b, err = caveats.MarshalMsgpack()
	assert.NoError(t, err)
	cs2, err = macaroon.DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, caveats, cs2)
}
