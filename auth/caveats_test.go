package auth

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
)

func TestCaveatSerialization(t *testing.T) {
	cs := macaroon.NewCaveatSet(
		RequireUser(123),
		RequireOrganization(123),
		RequireGoogleHD("123"),
		RequireGitHubOrg(123),
		ptr(FlyioUserID(123)),
		ptr(GitHubUserID(123)),
		(*GoogleUserID)(new(big.Int).SetBytes([]byte{
			0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF,
			123,
		})),
	)

	b, err := json.Marshal(cs)
	assert.NoError(t, err)

	cs2 := macaroon.NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)

	b, err = cs.MarshalMsgpack()
	assert.NoError(t, err)
	cs2, err = macaroon.DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)
}

func ptr[T any](t T) *T {
	return &t
}
