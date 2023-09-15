// package macaroon defines Fly.io's Macaroon token format.
//
// Tokens are created with [New], and refined with [Add] and [Add3P] to
// add conditions, called caveats. Their signature is updated as caveats
// are added. They're serialized with [Encode]
//
// Serialized tokens are parsed with [Decode], to get a [Macaroon]. To do
// real things with it, [Verify] it to receive the set of usable caveats.
//
// Serialized tokens can also be scanned with [DischargeMacaroon] to find
// caveats that need third-party discharges.
//
// Once fully parsed, a service using these tokens calls [Validate]
// to check the caveats.
package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	msgpack "github.com/vmihailenco/msgpack/v5"
)

const (
	// well-known locations
	LocationFlyioPermission     = "https://api.fly.io/v1"
	LocationFlyioAuthentication = "https://api.fly.io/aaa/v1"
	LocationFlyioSecrets        = "https://api.fly.io/secrets/v1"
)

// Macaroon is the fully-functioning internal representation of a
// token --- you've got a Macaroon either because you're constructing
// a new token yourself, or because you've parsed a token from the
// wire.
type Macaroon struct {
	Nonce         Nonce     `json:"-"`
	Location      string    `json:"location"`
	UnsafeCaveats CaveatSet `json:"caveats"`
	Tail          []byte    `json:"-"`

	newProof bool
}

func encode(v interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}

	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)

	enc.Reset(buf)
	enc.UseArrayEncodedStructs(true)
	enc.UseCompactInts(true)

	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// New creates a new token given a key-id string (which can
// be any opaque string and doesn't need to be cryptographically
// random or anything; the key-id is how you're going to relate
// the token back to a key you've saved somewhere; it's probably
// a database rowid somehow) and a location, which is ordinarily
// a URL. The key is the signing secret.
func New(kid []byte, loc string, key SigningKey) (*Macaroon, error) {
	return newMacaroon(kid, loc, key, false)
}

func newMacaroon(kid []byte, loc string, key SigningKey, isProof bool) (*Macaroon, error) {
	nonce := newNonce(kid, isProof)

	return &Macaroon{
		Location:      loc,
		Nonce:         nonce,
		Tail:          sign(key, nonce.MustEncode()),
		UnsafeCaveats: *NewCaveatSet(),
		newProof:      isProof,
	}, nil
}

// Decode parses a token off the wire; To get usable caveats, call
// Verify.
func Decode(buf []byte) (*Macaroon, error) {
	m := &Macaroon{}
	if err := msgpack.Unmarshal(buf, m); err != nil {
		return nil, fmt.Errorf("macaroon decode: %w", err)
	}

	return m, nil
}

// DecodeNonce parses just the nonce from an encoded macaroon.
func DecodeNonce(buf []byte) (Nonce, error) {
	var (
		nonceOnly = struct{ Nonce Nonce }{}
		err       = msgpack.Unmarshal(buf, &nonceOnly)
	)
	return nonceOnly.Nonce, err
}

// Add adds a caveat to a Macaroon, adjusting the tail signature in
// the process. This is how you'd "attenuate" a token, taking a
// read-write token and turning it into a read-only token, for instance.
func (m *Macaroon) Add(caveats ...Caveat) error {
	if m.Nonce.Proof && !m.newProof {
		return errors.New("can't add caveats to finalized proof")
	}

	var err error
	if caveats, err = m.dedup(caveats); err != nil {
		return fmt.Errorf("deduplicating caveats: %w", err)
	}

	seen3P := map[string]bool{}
	for _, cav := range GetCaveats[*Caveat3P](&m.UnsafeCaveats) {
		seen3P[cav.Location] = true
	}

	for _, caveat := range caveats {
		if caveat.IsAttestation() && !m.Nonce.Proof {
			return errors.New("cannot add attestations to non-proof macaroons")
		}

		if c3p, ok := caveat.(*Caveat3P); ok {
			// encrypt RN under the tail hmac so we can recover it during verification
			c3p.VID = seal(EncryptionKey(m.Tail), c3p.rn)

			if seen3P[c3p.Location] {
				return fmt.Errorf("m.add: attempting to add multiple 3ps for %s", c3p.Location)
			}
			seen3P[c3p.Location] = true
		}

		m.UnsafeCaveats.Caveats = append(m.UnsafeCaveats.Caveats, caveat)

		opc, err := NewCaveatSet(caveat).MarshalMsgpack()
		if err != nil {
			return fmt.Errorf("mint: encode caveat: %w", err)
		}

		m.Tail = sign(SigningKey(m.Tail), opc)

	}

	return nil
}

// remove elements from caveats that are already present in the macaroon or are
// duplicates within caveats.
//
// TODO: ignore caveats that are subsets of existing caveats
func (m *Macaroon) dedup(caveats []Caveat) ([]Caveat, error) {
	seen := make(map[string]bool, len(m.UnsafeCaveats.Caveats))

	for _, cav := range m.UnsafeCaveats.Caveats {
		packed, err := NewCaveatSet(cav).MarshalMsgpack()
		if err != nil {
			return nil, err
		}

		seen[hex.EncodeToString(packed)] = true
	}

	ret := make([]Caveat, 0, len(caveats))
	for _, cav := range caveats {
		packed, err := NewCaveatSet(cav).MarshalMsgpack()
		if err != nil {
			return nil, err
		}

		str := hex.EncodeToString(packed)
		if !seen[str] {
			ret = append(ret, cav)
			seen[str] = true
		}
	}

	return ret, nil
}

// Encode encodes a Macaroon to bytes after creating it
// or decoding it and adding more caveats.
func (m *Macaroon) Encode() ([]byte, error) {
	if m.Nonce.Proof && m.newProof {
		m.Tail = finalizeSignature(m.Tail)
		m.newProof = false
	}

	return encode(m)
}

// Verify checks the signature on a Decode()'ed Macaroon and returns the
// the set of caveats that require validation against the user's request.
// This excludes caveats that have already been validated (e.g. 3P caveats
// and others relating to the signing of the Macaroon).
func (m *Macaroon) Verify(k SigningKey, discharges [][]byte, trusted3Ps map[string]EncryptionKey) (*CaveatSet, error) {
	return m.verify(k, discharges, nil, true, trusted3Ps)
}

func (m *Macaroon) verify(k SigningKey, discharges [][]byte, parentTokenBindingIds [][]byte, trustAttestations bool, trusted3Ps map[string]EncryptionKey) (*CaveatSet, error) {
	if m.Nonce.Proof && m.newProof {
		return nil, errors.New("can't verify unfinalized proof")
	}

	if trusted3Ps == nil {
		trusted3Ps = map[string]EncryptionKey{}
	}

	dischargeByCID := make(map[string]*Macaroon, len(discharges))
	for _, dBuf := range discharges {
		decoded, err := Decode(dBuf)
		if err != nil {
			continue // ignore malformed discharges
		}

		dischargeByCID[string(decoded.Nonce.KID)] = decoded
	}

	curMac := sign(k, m.Nonce.MustEncode())

	ret := NewCaveatSet()

	type verifyParams struct {
		m *Macaroon
		k SigningKey
	}

	dischargesToVerify := make([]*verifyParams, 0, len(dischargeByCID))
	thisTokenBindingIds := [][]byte{digest(curMac)}

	for _, c := range m.UnsafeCaveats.Caveats {
		switch cav := c.(type) {
		case *Caveat3P:
			discharge, ok := dischargeByCID[string(cav.CID)]
			if !ok {
				return nil, errors.New("no matching discharge token")
			}

			dischargeKey, err := unseal(EncryptionKey(curMac), cav.VID)
			if err != nil {
				return nil, fmt.Errorf("macaroon verify: unseal VID for third-party caveat: %w", err)
			}

			dischargesToVerify = append(dischargesToVerify, &verifyParams{discharge, dischargeKey})
		case *BindToParentToken:
			// TODO @bento: this could be optimized
			found := false
			for _, bid := range parentTokenBindingIds {
				if bytes.HasPrefix(bid, *cav) {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("discharge bound to different parent token: %x", cav)
			}
		default:
			if cav.IsAttestation() && !m.Nonce.Proof {
				return nil, errors.New("attestation in non-proof macaroon")
			}

			if !cav.IsAttestation() || trustAttestations {
				ret.Caveats = append(ret.Caveats, c)
			}
		}

		opc, err := NewCaveatSet(c).MarshalMsgpack()
		if err != nil {
			return nil, err
		}

		curMac = sign(SigningKey(curMac), opc)
		thisTokenBindingIds = append(thisTokenBindingIds, digest(curMac))
	}

	for _, d := range dischargesToVerify {
		// If the discharge was actually created by a known third party we can
		// trust its attestations. Verify this by comparing signing key from
		// VID/CID.
		var trustedDischarge bool
		if ka, ok := trusted3Ps[d.m.Location]; ok {
			cidr, err := unseal(ka, d.m.Nonce.KID)
			if err != nil {
				return ret, fmt.Errorf("discharge cid decrypt: %w", err)
			}

			var cid wireCID
			if err = msgpack.Unmarshal(cidr, &cid); err != nil {
				return ret, fmt.Errorf("bad cid in discharge: %w", err)
			}

			if subtle.ConstantTimeCompare(d.k, cid.RN) != 1 {
				return ret, errors.New("discharge key from CID/VID mismatch")
			}

			trustedDischarge = true
		}

		dcavs, err := d.m.verify(
			d.k,
			nil, /* don't let them nest yet */
			thisTokenBindingIds,
			trustAttestations && trustedDischarge,
			trusted3Ps,
		)
		if err != nil {
			return nil, fmt.Errorf("macaroon verify: verify discharge: %w", err)
		}

		ret.Caveats = append(ret.Caveats, dcavs.Caveats...)
	}

	if m.Nonce.Proof {
		curMac = finalizeSignature(curMac)
	}

	if subtle.ConstantTimeCompare(curMac, m.Tail) != 1 {
		return nil, fmt.Errorf("macaroon verify: invalid")
	}

	return ret, nil
}

// finalizeSignature could conceptually just hash the macaroon tail. We're
// already using the truncated tail hash for token binding though. It wouldn't
// actually be bad to use the hash here, but HMAC feels better.
func finalizeSignature(tail []byte) []byte {
	h := hmac.New(sha256.New, []byte("proof-signature-finalization"))
	h.Write(tail)
	return h.Sum(nil)
}

// 16 bytes is a lot of bytes. The HMAC spec lets us truncate to half of the
// digest length, so it seems reasonable to do here also.
const bindingIdLength = sha256.Size / 2

// Bind binds this (discharge) token to the specified root token (parent) with
// a BindToParentToken caveat.
func (m *Macaroon) Bind(parent []byte) error {
	pm, err := Decode(parent)
	if err != nil {
		return fmt.Errorf("bind: decode parent: %w", err)
	}

	return m.BindToParentMacaroon(pm)
}

func (m *Macaroon) BindToParentMacaroon(parent *Macaroon) error {
	bid := digest(parent.Tail)[0:bindingIdLength]
	cav := BindToParentToken(bid)

	return m.Add(&cav)
}

// Add3P adds a third-party caveat to a Macaroon. A third-party
// caveat is checked not by evaluating what it means, but instead
// by looking for a "discharge token" --- a second token sent along
// with the token that says "some other service verified that the
// claims corresponding to this caveat are true".
//
// Add3P needs a key, which binds this token to the service that
// validates it. Every authentication caveat, for instance, shares
// an authentication key; the key connects the root service to the
// authentication service.
//
// Add3P takes a location, which is used to figure out which keys
// to use to check which caveats. The location is normally a URL. The
// authentication service has an authentication location URL.
func (m *Macaroon) Add3P(ka EncryptionKey, loc string, cs ...Caveat) error {
	if len(ka) != EncryptionKeySize {
		return fmt.Errorf("bad key size: have %d, need %d", len(ka), EncryptionKeySize)
	}

	// make a new root hmac key for the 3p discharge macaroon
	rn := NewSigningKey()

	// make the CID, which is consumed by the 3p service; then
	// encode and encrypt it
	cid := &wireCID{
		RN:      rn,
		Caveats: *NewCaveatSet(cs...),
	}

	cidBytes, err := encode(cid)
	if err != nil {
		return fmt.Errorf("encoding CID: %w", err)
	}

	m.Add(&Caveat3P{
		Location: loc,
		CID:      seal(ka, cidBytes),
		rn:       rn,
	})

	return nil
}

// ThirdPartyCIDs extracts the encrypted CIDs from a token's third party
// caveats. Each is identified by the location of the third party. The CID can
// then be exchanged with the third party for a discharge token. Third party
// caveats are checked against existing discharge tokens and discharged caveats
// are omitted from the results.
func (m *Macaroon) ThirdPartyCIDs(existingDischarges ...[]byte) (map[string][]byte, error) {
	ret := map[string][]byte{}
	dischargeCIDs := make(map[string]struct{}, len(existingDischarges))

	for _, ed := range existingDischarges {
		if n, err := DecodeNonce(ed); err == nil {
			dischargeCIDs[hex.EncodeToString(n.KID)] = struct{}{}
		}
	}

	for _, cav := range GetCaveats[*Caveat3P](&m.UnsafeCaveats) {
		if _, exists := ret[cav.Location]; exists {
			return nil, fmt.Errorf("extract third party caveats: duplicate locations: %s", cav.Location)
		}

		if _, discharged := dischargeCIDs[hex.EncodeToString(m.Nonce.KID)]; !discharged {
			ret[cav.Location] = cav.CID
		}
	}

	return ret, nil
}

// Checks the macaroon for a third party caveat for the specified location.
// Returns the caveat's encrypted CID, if found.
func (m *Macaroon) ThirdPartyCID(location string, existingDischarges ...[]byte) ([]byte, error) {
	cids, err := m.ThirdPartyCIDs(existingDischarges...)
	if err != nil {
		return nil, err
	}

	return cids[location], nil
}

// https://stackoverflow.com/questions/25065055/what-is-the-maximum-time-time-in-go
var maxTime = time.Unix(1<<63-62135596801, 999999999)

// Expiration calculates when this macaroon will expire
func (m *Macaroon) Expiration() time.Time {
	ret := maxTime

	for _, vw := range GetCaveats[*ValidityWindow](&m.UnsafeCaveats) {
		na := time.Unix(vw.NotAfter, 0)
		if na.Before(ret) {
			ret = na
		}
	}

	return ret
}
