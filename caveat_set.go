package macaroon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/superfly/macaroon/internal/merr"
	msgpack "github.com/vmihailenco/msgpack/v5"
)

// CaveatSet is how a set of caveats is serailized/encoded.
type CaveatSet struct {
	// The caveats encoded as necessary for macaroon signing/verification.
	// Access this via the PackedCaveats() method. When signing, each caveat is
	// encoded as a msgpack array containing the caveat type and the caveat body
	// (the same as a caveat set containing the one caveat). These encodings are
	// preserved from caveats sets we decode. This accounts for any variability
	// from different msgpack libraries in different languages.
	packedCaveats [][]byte

	// it's possible to build a CaveatSet that can't be msgpack encoded. We
	// track any error here so we can return it when something tries to get the
	// msgpack representation. This is mostly a thing when JSON decoding
	// unregistered caveat types.
	packErr error

	// Decoded caveats. Access this via the Caveats() method.
	caveats []Caveat
}

var (
	_ msgpack.CustomEncoder = (*CaveatSet)(nil)
	_ msgpack.CustomDecoder = (*CaveatSet)(nil)
	_ msgpack.Marshaler     = (*CaveatSet)(nil)
)

// NewCaveatSet creates a new CaveatSet comprised of the specified caveats.
func NewCaveatSet(caveats ...Caveat) *CaveatSet {
	c := &CaveatSet{caveats: []Caveat{}, packedCaveats: [][]byte{}}
	c.Add(caveats...)
	return c
}

// DecodeCaveats decodes a set of serialized caveats.
func DecodeCaveats(buf []byte) (*CaveatSet, error) {
	cavs := new(CaveatSet)

	if err := msgpack.Unmarshal(buf, cavs); err != nil {
		return nil, err
	}

	return cavs, nil
}

// Caveats are the decoded caveats.
func (c *CaveatSet) Caveats() []Caveat {
	return c.caveats
}

// PackedCaveats are the caveats, msgpack encoded for signing/verification.
func (c *CaveatSet) PackedCaveats() ([][]byte, error) {
	return c.packedCaveats, c.packErr
}

// Validates that the caveat set permits the specified accesses.
func (c *CaveatSet) Validate(accesses ...Access) error {
	return Validate(c, accesses...)
}

// Helper for validating concretely-typed accesses.
func Validate[A Access](cs *CaveatSet, accesses ...A) error {
	var err error
	for _, access := range accesses {
		if ferr := access.Validate(); ferr != nil {
			err = merr.Append(err, ferr)
			continue
		}

		err = merr.Append(err, cs.validateAccess(access))
	}

	return err
}

func (c *CaveatSet) validateAccess(access Access) error {
	var err error
	for _, caveat := range c.caveats {
		if IsAttestation(caveat) {
			continue
		}

		err = merr.Append(err, caveat.Prohibits(access))
	}

	return err
}

// GetCaveats gets any caveats of type T, including those nested within
// IfPresent caveats.
func GetCaveats[T Caveat](c *CaveatSet) (ret []T) {
	for _, cav := range c.caveats {
		if typed, ok := cav.(T); ok {
			ret = append(ret, typed)
		}

		if wc, isWrapper := cav.(WrapperCaveat); isWrapper {
			ret = append(ret, GetCaveats[T](wc.Unwrap())...)
		}
	}
	return ret
}

// Implements msgpack.Marshaler
func (c CaveatSet) MarshalMsgpack() ([]byte, error) {
	return encode(c)
}

// cavPrefix is the msgpack tag indicating an array of length 2.
const cavPrefix = byte(0x92)

// Implements msgpack.CustomEncoder
func (c CaveatSet) EncodeMsgpack(enc *msgpack.Encoder) error {
	if c.packErr != nil {
		return c.packErr
	}

	// TODO: resize enc buffer, since we know how much we're going to write?

	if err := enc.EncodeArrayLen(len(c.packedCaveats) * 2); err != nil {
		return err
	}

	for _, b := range c.packedCaveats {
		// each CaveatBytes is itself a caveat set (msgpack array len=2). Skip
		// the array tag when encoding them all together.
		if err := enc.Encode(msgpack.RawMessage(b[1:])); err != nil {
			return err
		}
	}

	return nil
}

// Implements msgpack.CustomDecoder
func (c *CaveatSet) DecodeMsgpack(dec *msgpack.Decoder) error {
	aLen, err := dec.DecodeArrayLen()
	if err != nil {
		return err
	}
	if aLen%2 != 0 {
		return errors.New("bad caveat container")
	}

	c.caveats = make([]Caveat, aLen/2)
	c.packedCaveats = make([][]byte, aLen/2)

	for i := 0; i < aLen/2; i++ {
		rawTyp, err := dec.DecodeRaw()
		if err != nil {
			return err
		}

		var typ CaveatType
		if err := msgpack.Unmarshal(rawTyp, &typ); err != nil {
			return err
		}

		rawCav, err := dec.DecodeRaw()
		if err != nil {
			return err
		}

		c.caveats[i] = typeToCaveat(CaveatType(typ))
		if err := msgpack.Unmarshal(rawCav, c.caveats[i]); err != nil {
			return err
		}

		c.packedCaveats[i] = make([]byte, 0, 1+len(rawTyp)+len(rawCav))
		c.packedCaveats[i] = append(c.packedCaveats[i], cavPrefix)
		c.packedCaveats[i] = append(c.packedCaveats[i], rawTyp...)
		c.packedCaveats[i] = append(c.packedCaveats[i], rawCav...)
	}

	return nil
}

func (c *CaveatSet) Add(caveats ...Caveat) {
	c.caveats = append(c.caveats, caveats...)

	if c.packErr != nil {
		return
	}

	for _, cav := range caveats {
		packed, err := packCaveat(cav)
		if err != nil {
			c.packedCaveats = nil
			c.packErr = err

			return
		}

		c.packedCaveats = append(c.packedCaveats, packed)
	}
}

func (c *CaveatSet) addWithPacked(cav Caveat, packed []byte) {
	c.caveats = append(c.caveats, cav)
	if c.packErr == nil {
		c.packedCaveats = append(c.packedCaveats, packed)
	}
}

func packCaveat(cav Caveat) ([]byte, error) {
	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)

	var buf bytes.Buffer
	configEncoder(enc, &buf)

	if err := enc.Encode(msgpack.RawMessage([]byte{cavPrefix})); err != nil {
		return nil, err
	}
	if err := enc.EncodeUint(uint64(cav.CaveatType())); err != nil {
		return nil, err
	}
	if err := enc.Encode(cav); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c CaveatSet) MarshalJSON() ([]byte, error) {
	var (
		jcavs = make([]jsonCaveat, len(c.caveats))
		err   error
	)

	for i := range c.caveats {
		ct := c.caveats[i].CaveatType()
		cts := caveatTypeToString(ct)
		if cts == "" {
			return nil, fmt.Errorf("unregistered caveat type: %d", ct)
		}

		jcavs[i] = jsonCaveat{
			Type: cts,
		}

		if jcavs[i].Body, err = json.Marshal(c.caveats[i]); err != nil {
			return nil, err
		}
	}

	return json.Marshal(jcavs)
}

func (c *CaveatSet) UnmarshalJSON(b []byte) error {
	jcavs := []jsonCaveat{}

	if err := json.Unmarshal(b, &jcavs); err != nil {
		return err
	}

	c.caveats = make([]Caveat, 0, len(jcavs))
	c.packedCaveats = make([][]byte, 0, len(jcavs))
	for i := range jcavs {
		t := caveatTypeFromString(jcavs[i].Type)

		cav := typeToCaveat(t)
		if err := json.Unmarshal(jcavs[i].Body, &cav); err != nil {
			return err
		}
		c.caveats = append(c.caveats, cav)

		if c.packErr == nil {
			if packed, err := packCaveat(cav); err != nil {
				c.packErr = err
				c.packedCaveats = nil
			} else {
				c.packedCaveats = append(c.packedCaveats, packed)
			}
		}

	}

	return nil
}

type jsonCaveat struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}
