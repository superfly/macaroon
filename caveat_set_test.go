package macaroon

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestJSON(t *testing.T) {
	var (
		m  = &Macaroon{Location: "https://api.fly.io", UnsafeCaveats: *NewCaveatSet(&ValidityWindow{NotBefore: 123, NotAfter: 234})}
		jm = []byte(`{"location":"https://api.fly.io","caveats":[{"type":"ValidityWindow","body":{"not_before":123,"not_after":234}}]}`)
	)

	m2 := new(Macaroon)
	assert.NoError(t, json.Unmarshal(jm, m2))
	assert.Equal(t, m, m2)

	jm2, err := json.Marshal(m)
	assert.NoError(t, err)
	assert.Equal(t, jm, jm2)
}

func TestCaveatSerialization(t *testing.T) {
	cs := NewCaveatSet(
		&ValidityWindow{NotBefore: 123, NotAfter: 234},
		&Caveat3P{Location: "123", VerifierKey: []byte("123"), Ticket: []byte("123")},
		&BindToParentToken{1, 2, 3},
	)

	b, err := json.Marshal(cs)
	assert.NoError(t, err)

	cs2 := NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)

	b, err = encode(cs)
	assert.NoError(t, err)
	cs2, err = DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)
}
