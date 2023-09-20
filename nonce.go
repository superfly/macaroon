package macaroon

import (
	"fmt"

	"github.com/google/uuid"
	msgpack "github.com/vmihailenco/msgpack/v5"
)

const nonceRndSize = 16

type nonceV0Fields struct {
	KID []byte `json:"kid"`
	Rnd []byte `json:"rnd"`
}

type nonceV1Fields struct {
	Proof bool `json:"proof"`
}

// A Nonce in cryptography is a random number that is only used
// once. A Nonce on a [Macaroon] is a blob of data that encodes,
// most impotantly, the "key ID" (KID) of the token; the KID is an
// opaque value that you, the library caller, provide when you create
// a token; it's the database key you use to tie the Macaroon to your
// database.
type Nonce struct {
	nonceV0Fields
	nonceV1Fields
	version int
}

var (
	_ msgpack.CustomDecoder = new(Nonce)
	_ msgpack.CustomEncoder = new(Nonce)
)

const (
	nonceV0 = iota
	nonceV1
	nonceVInvalid // keep this at end
)

var kidNamespace = uuid.MustParse("968fc2c6-a94f-4988-a544-2ad72b02f222")

// UUID is a simple globally unique identifier string for a nonce.
func (n *Nonce) UUID() uuid.UUID {
	kidUUID := uuid.NewSHA1(kidNamespace, n.KID)
	rndUUID := uuid.NewSHA1(kidUUID, n.Rnd)
	return rndUUID
}

// DecodeMsgpack implements [msgpack.CustomDecoder]
func (n *Nonce) DecodeMsgpack(d *msgpack.Decoder) error {
	// we encode structs as arrays, so adding new fields is tricky...
	// The Closed field was a later addition, so we handle 2 or 3 fields.

	nFields, err := d.DecodeArrayLen()
	if err != nil {
		return err
	}

	switch nFields {
	case 2:
		n.version = nonceV0
	case 3:
		n.version = nonceV1
	default:
		return fmt.Errorf("unknown nonce format: %d fields", nFields)
	}

	if n.version >= nonceV0 {
		if err = d.DecodeMulti(&n.nonceV0Fields.KID, &n.nonceV0Fields.Rnd); err != nil {
			return err
		}
	}

	if n.version >= nonceV1 {
		if err = d.DecodeMulti(&n.Proof); err != nil {
			return err
		}
	}

	return nil
}

// DecodeMsgpack implements [msgpack.CustomDecoder]
func (n *Nonce) EncodeMsgpack(e *msgpack.Encoder) error {
	var fields []any

	if n.version >= 0 {
		fields = append(fields, n.KID, n.Rnd)
	}

	if n.version >= 1 {
		fields = append(fields, n.Proof)
	}

	return e.Encode(fields)
}

func (n Nonce) MustEncode() []byte {
	b, err := encode(&n)

	// this can only fail if writing to the buffer fails.
	// it's convenienct to have a function that returns
	// a single value.
	if err != nil {
		panic(err)
	}

	return b
}

// newNonce creates a nonce from a key-id, where the key-id
// is any opaque string; the resulting nonce has a bunch of random
// goo in it to goo up the nonce. A sane key-id might be a user-id
// or org-id.
func newNonce(kid []byte, isProof bool) Nonce {
	return Nonce{
		nonceV0Fields{
			KID: kid,
			Rnd: rbuf(nonceRndSize),
		},
		nonceV1Fields{
			Proof: isProof,
		},
		nonceVInvalid - 1,
	}
}
