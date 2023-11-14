package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/auth"
	"github.com/superfly/macaroon/resset"
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

	for _, c := range caveats.Caveats {
		m, _ := macaroon.New(v.KID, v.Location, v.Key)
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
	for _, c := range caveats.Caveats {
		cpy := ptr(*aBase)
		cpy.UnsafeCaveats = *macaroon.NewCaveatSet()
		cpy.Add(c)
		cavsPacked, _ := cpy.UnsafeCaveats.MarshalMsgpack()
		cpyEnc, _ := cpy.Encode()
		v.Attenuation[aBaseHdr][base64.StdEncoding.EncodeToString(cavsPacked)] = macaroon.ToAuthorizationHeader(otherTok, cpyEnc, otherTok)
	}

	for _, c := range caveats.Caveats {
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
	ptr(stringCaveat("foo")),
	ptr(int64Caveat(-123)),
	ptr(uint64Caveat(123)),
	&sliceCaveat{1, 2, 3},
	&mapCaveat{"foo": "bar"},
	&intResourceSetCaveat{123: resset.ActionAll},
	&stringResourceSetCaveat{"foo": resset.ActionAll},
	&prefixResourceSetCaveat{"foo": resset.ActionAll},
	&structCaveat{
		StringField:            "foo",
		IntField:               -123,
		UintField:              123,
		SliceField:             []byte{1, 2, 3},
		MapField:               map[string]string{"foo": "bar"},
		IntResourceSetField:    resset.ResourceSet[uint64]{123: resset.ActionAll},
		StringResourceSetField: resset.ResourceSet[string]{"foo": resset.ActionAll},
		PrefixResourceSetField: resset.ResourceSet[resset.Prefix]{"foo": resset.ActionAll},
	},
	auth.RequireUser(123),
	auth.RequireOrganization(123),
	auth.RequireGoogleHD("123"),
	auth.RequireGitHubOrg(123),
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
func (c *mapCaveat) IsAttestation() bool               { return false }

type intResourceSetCaveat resset.ResourceSet[uint64]

func init()                                                       { macaroon.RegisterCaveatType(new(intResourceSetCaveat)) }
func (c *intResourceSetCaveat) CaveatType() macaroon.CaveatType   { return cavIntResourceSet }
func (c *intResourceSetCaveat) Name() string                      { return "IntResourceSet" }
func (c *intResourceSetCaveat) Prohibits(f macaroon.Access) error { return nil }

type stringResourceSetCaveat resset.ResourceSet[string]

func init()                                                          { macaroon.RegisterCaveatType(new(stringResourceSetCaveat)) }
func (c *stringResourceSetCaveat) CaveatType() macaroon.CaveatType   { return cavStringResourceSet }
func (c *stringResourceSetCaveat) Name() string                      { return "StringResourceSet" }
func (c *stringResourceSetCaveat) Prohibits(f macaroon.Access) error { return nil }

type prefixResourceSetCaveat resset.ResourceSet[resset.Prefix]

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
