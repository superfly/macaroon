package macaroon

import (
	"reflect"
	"strconv"
)

// A numeric identifier for caveat types. Values less than
// CavMinUserRegisterable (0x100000000) are reserved for use by fly.io. Users
// may request a globally-recognized caveat type via pull requests to this
// repository. Implementations that don't need to integrate with fly.io itself
// can pick from the user-defined range (>0x1000000000000).
type CaveatType uint64

const (
	CavFlyioOrganization CaveatType = iota
	_                               // deprecated
	CavFlyioVolumes
	CavFlyioApps
	CavValidityWindow
	CavFlyioFeatureSet
	CavFlyioMutations
	CavFlyioMachines
	CavAuthConfineUser
	CavAuthConfineOrganization
	CavFlyioIsUser
	Cav3P
	CavBindToParentToken
	CavIfPresent
	CavFlyioMachineFeatureSet
	CavFlyioFromMachineSource
	CavFlyioClusters
	_ // fly.io reserved
	_ // fly.io reserved
	CavAuthConfineGoogleHD
	CavAuthConfineGitHubOrg
	CavAuthMaxValidity

	// Globally-recognized user-registerable caveat types may be requested via
	// pull requests to this repository. Add a meaningful name of the caveat
	// type (e.g. CavAcmeCorpWidgetID) on the line prior to
	// CavMaxUserRegisterable.
	CavMinUserRegisterable CaveatType = 1 << 32
	CavMaxUserRegisterable CaveatType = 1<<48 - 1

	CavMinUserDefined CaveatType = 1 << 48
	CavMaxUserDefined CaveatType = 1<<64 - 2
	CavUnregistered   CaveatType = 1<<64 - 1
)

// Caveat is the interface implemented by all caveats.
type Caveat interface {
	// The numeric caveat type identifier.
	CaveatType() CaveatType

	// The string name of the caveat. Used for JSON encoding.
	Name() string

	// Callback for checking if the authorization check is blocked by this
	// caveat. Implementors must take care to return appropriate error types,
	// as they have bearing on the evaluation of IfPresent caveats.
	// Specifically, returning ErrResourceUnspecified indicates that caveat
	// constrains access to a resource type that isn't specified by the Access.
	Prohibits(f Access) error
}

// Attestations make a positive assertion rather than constraining access to a
// resource. Most caveats are not attestations. Attestations may only be
// included in Proofs (macaroons whose signature is finalized and cannot have
// more caveats appended by the user).
type Attestation interface {
	Caveat

	// Whether or not this caveat type is an attestation.
	IsAttestation() bool
}

func IsAttestation(c Caveat) bool {
	a, ok := c.(Attestation)
	return ok && a.IsAttestation()
}

// WrapperCaveat should be implemented by caveats that wrap other caveats (eg.
// resset.IfPresent).
type WrapperCaveat interface {
	Unwrap() *CaveatSet
}

var (
	t2c = map[CaveatType]Caveat{}
	s2t = map[string]CaveatType{}
	t2s = map[CaveatType]string{}
)

// Register a caveat type for use with this library.
func RegisterCaveatType(zeroValue Caveat) {
	typ := zeroValue.CaveatType()
	name := zeroValue.Name()

	if _, dup := t2c[typ]; dup {
		panic("duplicate caveat type")
	}
	if _, dup := t2s[typ]; dup {
		panic("duplicate caveat type")
	}
	if _, dup := s2t[name]; dup {
		panic("duplicate caveat type")
	}

	t2c[typ] = zeroValue
	t2s[typ] = name
	s2t[name] = typ
}

func unregisterCaveatType(zeroValue Caveat) {
	typ := zeroValue.CaveatType()
	name := zeroValue.Name()
	delete(t2c, typ)
	delete(t2s, typ)
	delete(s2t, name)
}

// Register an alternate name for this caveat type that will be recognized when
// decoding JSON.
func RegisterCaveatJSONAlias(typ CaveatType, alias string) {
	if _, dup := s2t[alias]; dup {
		panic("duplicate caveat type")
	}
	if _, exist := t2s[typ]; !exist {
		panic("unregistered caveat type")
	}
	s2t[alias] = typ
}

func typeToCaveat(t CaveatType) Caveat {
	cav, ok := t2c[t]
	if !ok {
		return &UnregisteredCaveat{Type: t}
	}

	ct := reflect.TypeOf(cav)
	if ct.Kind() == reflect.Pointer {
		return reflect.New(ct.Elem()).Interface().(Caveat)
	}
	return reflect.Zero(ct).Interface().(Caveat)
}

func caveatTypeFromString(s string) CaveatType {
	if t, ok := s2t[s]; ok {
		return t
	}
	if t, err := strconv.ParseUint(s, 10, 64); err == nil {
		return CaveatType(t)
	}

	return CavUnregistered
}

func caveatTypeToString(t CaveatType) string {
	if s, ok := t2s[t]; ok && t < CavMinUserDefined {
		return s
	}
	return strconv.FormatUint(uint64(t), 10)
}
