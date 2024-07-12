// Package macaroon defines Fly.io's Macaroon token format.
//
// A [Macaroon] is a flexible bearer token based on the idea of
// "caveats". A caveat limits what a Macaroon can do. A blank Macaroon
// might represent an all-access credential; a caveat layered onto that Macaroon
// might transform it into a read-only credential; a further caveat might
// create a credential that can only read, and only to a particular file.
//
// The basic laws of Macaroons:
//
//   - Anybody can add a caveat onto a Macaroon, even if they didn't
//     originally issue it.
//   - A caveat can only further restrict a Macaroon's access; adding
//     a caveat can't even increase access.
//   - Given a Macaroon with a set of caveats (A, B, C), it's
//     cryptographically impossible to remove any caveat, to
//     produce an (A, B) Macaroon or a (B, C).
//
// An ordinary caveat is checked by looking at the request and the caveat
// and seeing if they match up. For instance, a Macaroon with an
// `Operation=read` caveat can be checked by looking to see if the request
// it accompanies is trying to write. Simple stuff.
//
// A "third party (3P)" caveat works differently. 3P caveats demand
// that some other named system validate the request.
//
// Users extract a little ticket from the 3P caveat and hands it to the third
// party, along with anything else the third party might want. That third party
// resolves the caveat by generating a "discharge Macaroon", which is a whole
// 'nother token, tied cryptographically to the original 3P
// caveat. The user then presents both the original Macaroon and the
// discharge Macaroon with their request.
//
// For instance: most Fly.io Macaroons require a logged-in user (usually
// a member of a particular organization). We express that with a 3P
// caveat pointing to our authentication endpoint. That endpoint checks
// to see who you're logged in as, and produces an appropriate discharge,
// which accompanies the original Macaroon and (in effect) attests to
// you being logged in.
//
// # Cryptography
//
// All the cryptography in Macaroons is symmetric; there are no public
// keys.
//
// We use SHA256 as our hash, and HMAC-SHA256 as our authenticator.
//
// We use ChaCha20/Poly1305 as the AEAD for third-party caveats.
//
// # Fly Macaroon Format
//
// Our Macaroons are simple structs encoded with [MessagePack]. We use
// a binary encoding both for performance and to to encode deterministically,
// for cryptography. MessagePack is extraordinarily simple and you can reason
// about this code as if simply used JSON.
//
// A typical Fly.io request from a user will require multiple tokens;
// the original "root" token, which says what you're allowed to do, and
// tokens to validate 3P caveats (usually at least an authentication
// token).
//
// To represent that bundle of tokens, we define a `FlyV1` HTTP
// `Authorization` header scheme, which is simply a comma-separated
// set of Base64'd Macaroons.
//
// # Internal Deployment
//
// See the `flyio` package for more details.
//
// # Basic Library Usage
//
//   - Create a token with [New].
//
//   - Add caveats ("attenuating" it) with [Macaroon.Add].
//
//   - Sign and encode the token with [Macaroon.Encode].
//
//   - Decode a binary token with [Decode].
//
//   - Verify the signatures on a token with [Macaroon.Verify]. Note that
//     the whole token has not been checked at this point!
//
//   - Check the caveats (the result of [Macaroon.Verify]) with [CaveatSet.Validate].
//
// [Macaroon]: https://storage.googleapis.com/pub-tools-public-publication-data/pdf/41892.pdf
// [MessagePack]: https://msgpack.org/index.html
//
// [API Tokens]: https://fly.io/blog/api-tokens-a-tedious-survey/
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

// Macaroon is the fully-functioning internal representation of a
// token --- you've got a Macaroon either because you're constructing
// a new token yourself, or because you've parsed a token from the
// wire.
//
// Some fields in these structures are JSON-encoded because we use
// a JSON representation of Macaroons in IPC with our Rails API, which
// doesn't have a good FFI to talk to Go.
type Macaroon struct {
	Nonce    Nonce  `json:"-"`
	Location string `json:"location"`

	// Retrieve caveats from a Macaroon you don't trust
	// by calling [Macaroon.Verify], not by poking into
	// the struct.
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

// Decode parses a token off the wire; to get usable caveats. There
// are two things you can do with a freshly-decoded Macaroon:
//
//   - You can verify the signature and recover the caveats with [Macaroon.Verify]
//
//   - You can add additional caveats to the Macaroon with [Macaroon.Add], and then
//     call [Macaroon.Encode] to re-encode it (this is called "attenuation", and
//     it's what you'd do to take a read-write token and make it a read-only
//     token, for instance.
//
// Note that calling [Macaroon.Verify] requires a secret key, but
// [Macaroon.Add] and [Macaroon.Encode] does not. That's a Macaroon
// magic power.
func Decode(buf []byte) (*Macaroon, error) {
	m := &Macaroon{}
	if err := msgpack.Unmarshal(buf, m); err != nil {
		return nil, fmt.Errorf("macaroon decode: %w", err)
	}

	return m, nil
}

// DecodeNonce parses just the [Nonce] from an encoded [Macaroon].
// You'd want to do this, for instance, to look metadata up by the
// keyid of the [Macaroon], which is encoded in the [Nonce].
func DecodeNonce(buf []byte) (nonce Nonce, err error) {
	dec := msgpack.NewDecoder(bytes.NewReader(buf))

	var n int
	switch n, err = dec.DecodeArrayLen(); {
	case err != nil:
		return
	case n == 0:
		err = errors.New("bad nonce")
		return
	}

	err = dec.Decode(&nonce)
	return
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
		if IsAttestation(caveat) && !m.Nonce.Proof {
			return errors.New("cannot add attestations to non-proof macaroons")
		}

		if c3p, ok := caveat.(*Caveat3P); ok {
			// encrypt RN under the tail hmac so we can recover it during verification
			c3p.VerifierKey = seal(EncryptionKey(m.Tail), c3p.rn)

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

// Verify checks the signature on a [Macaroon.Decode] 'ed Macaroon and returns the
// the set of caveats that require validation against the user's request.
//
// Verify is the primary way you recover caveats from a Macaroon. Note that
// the caveats returned are the semantically meaningful subset of caveats that
// might need to be checked against the request. Third-party caveats are
// validated implicitly by checking sgnatures, and aren't returned by
// Verify.
//
// (A fun wrinkle, though: a 3P discharge token can add additional ordinary caveats
// to a token; you can, for instance, discharge our authentication token with
// a token that says "yes, this person is logged in as bob@victim.com, but
// only allow this request to perform reads, not writes"). Those added
// ordinary caveats WILL be returned from Verify.
func (m *Macaroon) Verify(k SigningKey, discharges [][]byte, trusted3Ps map[string][]EncryptionKey) (*CaveatSet, error) {
	dms := make([]*Macaroon, 0, len(discharges))
	for _, d := range discharges {
		dm, err := Decode(d)
		if err != nil {
			// ignore malformed discharges
			continue
		}

		dms = append(dms, dm)
	}

	return m.VerifyParsed(k, dms, trusted3Ps)
}

func (m *Macaroon) VerifyParsed(k SigningKey, dms []*Macaroon, trusted3Ps map[string][]EncryptionKey) (*CaveatSet, error) {
	return m.verify(k, dms, nil, true, trusted3Ps)
}

func (m *Macaroon) verify(k SigningKey, dms []*Macaroon, parentTokenBindingIds [][]byte, trustAttestations bool, trusted3Ps map[string][]EncryptionKey) (*CaveatSet, error) {
	if m.Nonce.Proof && m.newProof {
		return nil, errors.New("can't verify unfinalized proof")
	}

	if trusted3Ps == nil {
		trusted3Ps = map[string][]EncryptionKey{}
	}

	dmsByTicket := make(map[string][]*Macaroon, len(dms))
	for _, dm := range dms {
		skid := string(dm.Nonce.KID)
		dmsByTicket[skid] = append(dmsByTicket[skid], dm)
	}

	curMac := sign(k, m.Nonce.MustEncode())

	ret := NewCaveatSet()

	type verifyParams struct {
		m []*Macaroon
		k SigningKey
	}

	dischargesToVerify := make([]*verifyParams, 0, len(dmsByTicket))
	thisTokenBindingIds := [][]byte{digest(curMac)}

	for _, c := range m.UnsafeCaveats.Caveats {
		switch cav := c.(type) {
		case *Caveat3P:
			discharges, ok := dmsByTicket[string(cav.Ticket)]
			if !ok {
				return nil, errors.New("no matching discharge token")
			}

			dischargeKey, err := unseal(EncryptionKey(curMac), cav.VerifierKey)
			if err != nil {
				return nil, fmt.Errorf("macaroon verify: unseal VerifierKey for third-party caveat: %w", err)
			}

			dischargesToVerify = append(dischargesToVerify, &verifyParams{discharges, dischargeKey})
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
			if IsAttestation(cav) && !m.Nonce.Proof {
				return nil, errors.New("attestation in non-proof macaroon")
			}

			if !IsAttestation(cav) || trustAttestations {
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

	for _, vp := range dischargesToVerify {
		var (
			discharged bool
			dErr       error
		)

	dmLoop:
		for _, dm := range vp.m {
			// If the discharge was actually created by a known third party we can
			// trust its attestations. Verify this by comparing signing key from
			// VerifierKey/ticket.
			var trustedDischarge bool

		trustLoop:
			for _, ka := range trusted3Ps[dm.Location] {
				ticketr, err := unseal(ka, dm.Nonce.KID)
				if err != nil {
					continue trustLoop
				}

				var ticket wireTicket
				if err = msgpack.Unmarshal(ticketr, &ticket); err != nil {
					dErr = errors.Join(dErr, fmt.Errorf("bad ticket in discharge: %w", err))
					continue dmLoop
				}

				if subtle.ConstantTimeCompare(vp.k, ticket.DischargeKey) != 1 {
					dErr = errors.Join(dErr, errors.New("discharge key from ticket/VerifierKey mismatch"))
					continue dmLoop
				}

				trustedDischarge = true
				break trustLoop
			}

			dcavs, err := dm.verify(
				vp.k,
				nil, /* don't let them nest yet */
				thisTokenBindingIds,
				trustAttestations && trustedDischarge,
				trusted3Ps,
			)
			if err != nil {
				dErr = errors.Join(dErr, fmt.Errorf("macaroon verify: verify discharge: %w", err))
				continue dmLoop
			}

			ret.Caveats = append(ret.Caveats, dcavs.Caveats...)
			discharged = true
			break dmLoop
		}

		if !discharged {
			return nil, dErr
		}
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

// Bind cryptographically binds a discharge token to the "parent"
// token it's meant to accompany. This is a convenience method
// that takes a raw unparsed parent token as an argument.
//
// Discharge tokens are generated by third-party services (like
// our authentication service, or your Slack bot) to satisfy a
// third-party caveat. Users present both the original and the
// discharge token when they make requests. Discharge tokens
// must be bound when they're sent; doing so prevents Discharge
// tokens from being replayed in some other context.
func (m *Macaroon) Bind(parent []byte) error {
	pm, err := Decode(parent)
	if err != nil {
		return fmt.Errorf("bind: decode parent: %w", err)
	}

	return m.BindToParentMacaroon(pm)
}

// See [Macaroon.Bind]; this is that function, but it takes a
// parsed Macaroon.
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

	// make the ticket, which is consumed by the 3p service; then
	// encode and encrypt it
	ticket := &wireTicket{
		DischargeKey: rn,
		Caveats:      *NewCaveatSet(cs...),
	}

	ticketBytes, err := encode(ticket)
	if err != nil {
		return fmt.Errorf("encoding ticket: %w", err)
	}

	m.Add(&Caveat3P{
		Location: loc,
		Ticket:   seal(ka, ticketBytes),
		rn:       rn,
	})

	return nil
}

// ThirdPartyTickets extracts the encrypted tickets from a token's third party
// caveats.
//
// The ticket of a third-party caveat is a little ticket embedded in the
// caveat that is readable by the third-party service for which it's
// intended. That service uses the ticket to generate a compatible discharge
// token to satisfy the caveat.
//
// Macaroon services of all types are identified by their "location",
// which in our scheme is always a URL. ThirdPartyTickets returns a map
// of location to ticket. In a perfect world, you could iterate over this
// map hitting each URL and passing it the associated ticket, collecting
// all the discharge tokens you need for the request (it is never that
// simple, though).
//
// Already-discharged caveats are excluded from the results.
func (m *Macaroon) ThirdPartyTickets(existingDischarges ...[]byte) (map[string][]byte, error) {
	ret := map[string][]byte{}
	dischargeTickets := make(map[string]struct{}, len(existingDischarges))

	for _, ed := range existingDischarges {
		if n, err := DecodeNonce(ed); err == nil {
			dischargeTickets[hex.EncodeToString(n.KID)] = struct{}{}
		}
	}

	for _, cav := range GetCaveats[*Caveat3P](&m.UnsafeCaveats) {
		if _, exists := ret[cav.Location]; exists {
			return nil, fmt.Errorf("extract third party caveats: duplicate locations: %s", cav.Location)
		}

		if _, discharged := dischargeTickets[hex.EncodeToString(cav.Ticket)]; !discharged {
			ret[cav.Location] = cav.Ticket
		}
	}

	return ret, nil
}

// ThirdPartyTicket returns the ticket (see [Macaron.ThirdPartyTickets]) associated
// with a URL location, if possible.
func (m *Macaroon) ThirdPartyTicket(location string, existingDischarges ...[]byte) ([]byte, error) {
	tickets, err := m.ThirdPartyTickets(existingDischarges...)
	if err != nil {
		return nil, err
	}

	return tickets[location], nil
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

// String encoded token with `fm2_` prefix.
func (m *Macaroon) String() (string, error) {
	tok, err := m.Encode()
	if err != nil {
		return "", err
	}

	return encodeTokens(tok), nil
}
