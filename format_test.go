package macaroon

import (
	"encoding/base64"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestTokenFormat(t *testing.T) {
	var (
		kid = rbuf(10)
		ka  = NewEncryptionKey()
		key = NewSigningKey()
	)

	m, err := New(kid, "root", key)
	assert.NoError(t, err)
	m.Add(cavParent(ActionRead, 110))
	m.Add3P(ka, "auth")
	buf, err := m.Encode()
	assert.NoError(t, err)

	found, dcavs, dm, err := dischargeMacaroon(ka, "auth", buf)
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, 0, len(dcavs))

	dbuf, err := dm.Encode()
	assert.NoError(t, err)

	tokenHdr := encodeTokens(buf, dbuf)

	authHdr := ToAuthorizationHeader(buf, dbuf)

	t.Logf("%s", authHdr)

	permissionToken, dischargeTokens, err := ParsePermissionAndDischargeTokens(authHdr, "root")
	assert.Equal(t, permissionToken, buf)
	assert.Equal(t, 1, len(dischargeTokens))
	assert.Equal(t, dbuf, dischargeTokens[0])
	assert.NoError(t, err)

	permissionToken, dischargeTokens, err = ParsePermissionAndDischargeTokens(tokenHdr, "root")
	assert.Equal(t, permissionToken, buf)
	assert.Equal(t, 1, len(dischargeTokens))
	assert.Equal(t, dbuf, dischargeTokens[0])
	assert.NoError(t, err)

	t.Logf("%v %v", permissionToken, dischargeTokens)
}

func TestParseTokenListWhitespace(t *testing.T) {
	var (
		tok1 = []byte("first token")
		tok2 = []byte("second token")
		enc1 = "fm2_" + base64.StdEncoding.EncodeToString(tok1)
		enc2 = "fm2_" + base64.StdEncoding.EncodeToString(tok2)
	)

	for name, hdr := range map[string]string{
		"comma":               "FlyV1 " + enc1 + "," + enc2,
		"comma space":         "FlyV1 " + enc1 + ", " + enc2,
		"space around comma":  "FlyV1 " + enc1 + " , " + enc2,
		"comma tab":           "FlyV1 " + enc1 + ",\t" + enc2,
		"trailing whitespace": "FlyV1 " + enc1 + "," + enc2 + " ",
	} {
		t.Run(name, func(t *testing.T) {
			toks, err := Parse(hdr)
			assert.NoError(t, err)
			assert.Equal(t, [][]byte{tok1, tok2}, toks)
		})
	}
}
