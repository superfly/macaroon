package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"

	"golang.org/x/exp/slices"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/auth"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
	msgpack "github.com/vmihailenco/msgpack/v5"
	"golang.org/x/exp/maps"
)

func main() {
	v := &vectors{
		Location:  randHex(16),
		Key:       macaroon.NewSigningKey(),
		TPKey:     macaroon.NewEncryptionKey(),
		Macaroons: map[string]string{},

		// map[baseMacaroon]map[caveatsBeingAdded]resultingMacaroon
		Attenuation: map[string]map[string]string{},
		Caveats:     map[string][]byte{},
	}
	v.KID = keyFingerprint(v.Key)

	for _, c := range caveats.Caveats() {
		m, _ := macaroon.New(v.KID, v.Location, v.Key)

		// put attestations in discharge tokens
		if macaroon.IsAttestation(c) {
			k := macaroon.NewEncryptionKey()
			m.Add3P(k, v.Location)
			ticket, _ := m.ThirdPartyTicket(v.Location)
			_, dm, _ := macaroon.DischargeTicket(k, v.Location, ticket)
			m = dm
		}

		m.Add(c)
		tok, _ := m.Encode()
		v.Macaroons[c.Name()] = macaroon.ToAuthorizationHeader(tok)
	}

	other, _ := macaroon.New([]byte{1, 2, 3}, "other loc", macaroon.NewSigningKey())
	otherTok, _ := other.Encode()

	aBase, _ := macaroon.New(v.KID, v.Location, v.Key)
	aBaseTok, _ := aBase.Encode()
	aBaseHdr := macaroon.ToAuthorizationHeader(otherTok, aBaseTok, otherTok)
	v.Attenuation[aBaseHdr] = map[string]string{}
	for _, c := range caveats.Caveats() {
		cpy := ptr(*aBase)
		cpy.UnsafeCaveats = *macaroon.NewCaveatSet()
		cpy.Add(c)
		cavsPacked, _ := cpy.UnsafeCaveats.MarshalMsgpack()
		cpyEnc, _ := cpy.Encode()
		v.Attenuation[aBaseHdr][base64.StdEncoding.EncodeToString(cavsPacked)] = macaroon.ToAuthorizationHeader(otherTok, cpyEnc, otherTok)
	}

	for _, c := range caveats.Caveats() {
		v.Caveats[c.Name()] = pack(c)
	}

	v.Caveats["zeroUint64Caveat"] = pack(ptr(uint64Caveat(0)))
	v.Caveats["smallUint64Caveat"] = pack(ptr(uint64Caveat(1)))
	v.Caveats["bigUint64Caveat"] = pack(ptr(uint64Caveat(math.MaxUint64)))

	withTP := ptr(*aBase)
	withTP.UnsafeCaveats = *macaroon.NewCaveatSet()
	withTP.Add3P(v.TPKey, "discharged")
	withTP.Add3P(v.TPKey, "undischarged")
	ticket, _ := withTP.ThirdPartyTicket("discharged")
	_, dm, _ := macaroon.DischargeTicket(v.TPKey, "discharged", ticket)
	dmTok, _ := dm.Encode()
	permTok, _ := withTP.Encode()
	v.WithTPs = macaroon.ToAuthorizationHeader(permTok, dmTok)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}

type vectors struct {
	Location    string                       `json:"location"`
	Key         []byte                       `json:"key"`
	TPKey       []byte                       `json:"tp_key"`
	KID         []byte                       `json:"kid"`
	Macaroons   map[string]string            `json:"macaroons"`
	Attenuation map[string]map[string]string `json:"attenuation"`
	Caveats     map[string][]byte            `json:"caveats"`
	WithTPs     string                       `json:"with_tps"`
}

var caveats = macaroon.NewCaveatSet(
	&macaroon.BindToParentToken{1, 2, 3},
	ptr(stringCaveat("foo")),
	ptr(int64Caveat(-123)),
	ptr(uint64Caveat(123)),
	&sliceCaveat{1, 2, 3},
	&mapCaveat{"c": "c", "a": "a", "b": "b"},
	&intResourceSetCaveat{Body: resset.ResourceSet[uint64]{3: resset.ActionAll, 1: resset.ActionAll, 2: resset.ActionAll}},
	&stringResourceSetCaveat{Body: resset.ResourceSet[string]{"c": resset.ActionAll, "a": resset.ActionAll, "b": resset.ActionAll}},
	&prefixResourceSetCaveat{Body: resset.ResourceSet[resset.Prefix]{"c": resset.ActionAll, "a": resset.ActionAll, "b": resset.ActionAll}},
	&structCaveat{
		StringField:            "foo",
		IntField:               -123,
		UintField:              123,
		SliceField:             []byte{1, 2, 3},
		MapField:               map[string]string{"c": "c", "a": "a", "b": "b"},
		IntResourceSetField:    resset.ResourceSet[uint64]{3: resset.ActionAll, 1: resset.ActionAll, 2: resset.ActionAll},
		StringResourceSetField: resset.ResourceSet[string]{"c": resset.ActionAll, "a": resset.ActionAll, "b": resset.ActionAll},
		PrefixResourceSetField: resset.ResourceSet[resset.Prefix]{"c": resset.ActionAll, "a": resset.ActionAll, "b": resset.ActionAll},
	},
	auth.RequireUser(123),
	auth.RequireOrganization(123),
	auth.RequireGoogleHD("123"),
	auth.RequireGitHubOrg(123),
	ptr(auth.FlyioUserID(123)),
	ptr(auth.GitHubUserID(123)),
	(*auth.GoogleUserID)(new(big.Int).SetBytes([]byte{
		0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF,
		123,
	})),
	&flyio.NoAdminFeatures{},
	&flyio.Organization{ID: 123, Mask: resset.ActionAll},
)

const (
	cavString = macaroon.CavMinUserDefined + iota
	cavInt64
	cavUint64
	cavSlice
	cavMap
	cavIntResourceSet
	cavStringResourceSet
	cavPrefixResourceSet
	cavStruct
)

type stringCaveat string

func init() { macaroon.RegisterCaveatType(new(stringCaveat)) }

func (c *stringCaveat) CaveatType() macaroon.CaveatType   { return cavString }
func (c *stringCaveat) Name() string                      { return "String" }
func (c *stringCaveat) Prohibits(f macaroon.Access) error { return nil }

type int64Caveat int64

func init() { macaroon.RegisterCaveatType(new(int64Caveat)) }

func (c *int64Caveat) CaveatType() macaroon.CaveatType   { return cavInt64 }
func (c *int64Caveat) Name() string                      { return "Int64" }
func (c *int64Caveat) Prohibits(f macaroon.Access) error { return nil }

type uint64Caveat uint64

func init()                                               { macaroon.RegisterCaveatType(new(uint64Caveat)) }
func (c *uint64Caveat) CaveatType() macaroon.CaveatType   { return cavUint64 }
func (c *uint64Caveat) Name() string                      { return "Uint64" }
func (c *uint64Caveat) Prohibits(f macaroon.Access) error { return nil }

type sliceCaveat []byte

func init()                                              { macaroon.RegisterCaveatType(new(sliceCaveat)) }
func (c *sliceCaveat) CaveatType() macaroon.CaveatType   { return cavSlice }
func (c *sliceCaveat) Name() string                      { return "Slice" }
func (c *sliceCaveat) Prohibits(f macaroon.Access) error { return nil }

type mapCaveat map[string]string

func init()                                            { macaroon.RegisterCaveatType(new(mapCaveat)) }
func (c *mapCaveat) CaveatType() macaroon.CaveatType   { return cavMap }
func (c *mapCaveat) Name() string                      { return "Map" }
func (c *mapCaveat) Prohibits(f macaroon.Access) error { return nil }

var _ msgpack.CustomEncoder = mapCaveat{}

func (c mapCaveat) EncodeMsgpack(enc *msgpack.Encoder) error {
	enc.EncodeMapLen(len(c))

	// map ordering is random and we need canonical encoding
	keys := maps.Keys(c)
	slices.Sort(keys)

	for _, k := range keys {
		enc.Encode(k)
		enc.Encode(c[k])
	}

	return nil
}

type intResourceSetCaveat struct {
	Body resset.ResourceSet[uint64]
}

func init()                                                       { macaroon.RegisterCaveatType(new(intResourceSetCaveat)) }
func (c *intResourceSetCaveat) CaveatType() macaroon.CaveatType   { return cavIntResourceSet }
func (c *intResourceSetCaveat) Name() string                      { return "IntResourceSet" }
func (c *intResourceSetCaveat) Prohibits(f macaroon.Access) error { return nil }

type stringResourceSetCaveat struct {
	Body resset.ResourceSet[string]
}

func init()                                                          { macaroon.RegisterCaveatType(new(stringResourceSetCaveat)) }
func (c *stringResourceSetCaveat) CaveatType() macaroon.CaveatType   { return cavStringResourceSet }
func (c *stringResourceSetCaveat) Name() string                      { return "StringResourceSet" }
func (c *stringResourceSetCaveat) Prohibits(f macaroon.Access) error { return nil }

type prefixResourceSetCaveat struct {
	Body resset.ResourceSet[resset.Prefix]
}

func init()                                                          { macaroon.RegisterCaveatType(new(prefixResourceSetCaveat)) }
func (c *prefixResourceSetCaveat) CaveatType() macaroon.CaveatType   { return cavPrefixResourceSet }
func (c *prefixResourceSetCaveat) Name() string                      { return "PrefixResourceSet" }
func (c *prefixResourceSetCaveat) Prohibits(f macaroon.Access) error { return nil }

type structCaveat struct {
	StringField            string
	IntField               int64
	UintField              uint64
	SliceField             []byte
	MapField               map[string]string
	IntResourceSetField    resset.ResourceSet[uint64]
	StringResourceSetField resset.ResourceSet[string]
	PrefixResourceSetField resset.ResourceSet[resset.Prefix]
}

func init()                                               { macaroon.RegisterCaveatType(new(structCaveat)) }
func (c *structCaveat) CaveatType() macaroon.CaveatType   { return cavStruct }
func (c *structCaveat) Name() string                      { return "Struct" }
func (c *structCaveat) Prohibits(f macaroon.Access) error { return nil }

var _ msgpack.CustomEncoder = mapCaveat{}

func (c structCaveat) EncodeMsgpack(enc *msgpack.Encoder) error {
	enc.EncodeArrayLen(8)
	enc.Encode(c.StringField)
	enc.Encode(c.IntField)
	enc.Encode(c.UintField)
	enc.Encode(c.SliceField)

	// map ordering is random and we need canonical encoding
	enc.EncodeMapLen(len(c.MapField))
	keys := maps.Keys(c.MapField)
	slices.Sort(keys)

	for _, k := range keys {
		enc.Encode(k)
		enc.Encode(c.MapField[k])
	}

	enc.Encode(c.IntResourceSetField)
	enc.Encode(c.StringResourceSetField)
	enc.Encode(c.PrefixResourceSetField)

	return nil
}

func keyFingerprint(key []byte) []byte {
	digest := sha256.Sum256(key)
	return digest[:16]
}

func randHex(n int) string {
	return hex.EncodeToString(randBytes(n))
}

func randBytes(n int) []byte {
	buf := make([]byte, n)
	rand.Read(buf)
	return buf
}

func ptr[T any](v T) *T {
	return &v
}

func pack(caveats ...macaroon.Caveat) []byte {
	cs, _ := macaroon.NewCaveatSet(caveats...).MarshalMsgpack()
	return cs
}
