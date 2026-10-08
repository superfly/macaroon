package macaroon

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/vmihailenco/msgpack/v5"
)

// The caveat container's array length comes from the wire and must not
// drive memory reservation: a header that promises millions of caveats
// backed by no data has to fail cheaply.
func TestDecodeCaveatSetOversizedHeader(t *testing.T) {
	const claimedCaveats = 1 << 21

	var buf bytes.Buffer
	assert.NoError(t, msgpack.NewEncoder(&buf).EncodeArrayLen(claimedCaveats*2))
	header := buf.Bytes()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var cs CaveatSet
	err := msgpack.NewDecoder(bytes.NewReader(header)).Decode(&cs)

	runtime.ReadMemStats(&after)

	assert.Error(t, err)
	assert.Equal(t, 0, len(cs.Caveats))

	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 1<<20 {
		t.Fatalf("decoding a %d-byte header allocated %d bytes", len(header), allocated)
	}
}
