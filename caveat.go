package macaroon

import (
	"fmt"
	"reflect"
)

// A numeric identifier for caveat types. Values less than
// CavMinUserRegisterable (0x100000000) are reserved for use by fly.io. Users
// may request a globally-recognized caveat type via pull requests to this
// repository. Implementations that don't need to integrate with fly.io itself
// can pick from the user-defined range (>0x1000000000000).
type CaveatType uint64

const (
	_ CaveatType = iota // fly.io reserved
	_                   // fly.io reserved
	_                   // fly.io reserved
	_                   // fly.io reserved
	CavValidityWindow
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved
	Cav3P
	CavBindToParentToken
	CavIfPresent
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved
	_ // fly.io reserved

	// Globally-recognized user-registerable caveat types may be requested via
	// pull requests to this repository. Add a meaningful name of the caveat
	// type (e.g. CavAcmeCorpWidgetID) on the line prior to
	// CavMaxUserRegisterable.
	CavMinUserRegisterable = 1 << 32
	CavMaxUserRegisterable = 1<<48 - 1

	CavMinUserDefined = 1 << 48
	CavMaxUserDefined = 1<<64 - 2
	CavUnregistered   = 1<<64 - 1
)

// Caveat is the interface implemented by all caveats.
type Caveat interface {
	// The numeric caveat type identifier.
	CaveatType() CaveatType

	// Callback for checking if the authorization check is blocked by this
	// caveat. Implementors must take care to return appropriate error types,
	// as they have bearing on the evaluation of IfPresent caveats.
	// Specifically, returning ErrResourceUnspecified indicates that caveat
	// constrains access to a resource type that isn't specified by the Access.
	Prohibits(f Access) error

	// Whether or not this caveat type is an attestation. Attestations make a
	// positive assertion rather than constraining access to a resource. Most
	// caveats are not attestations.
	IsAttestation() bool
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
func RegisterCaveatType(name string, typ CaveatType, zeroValue Caveat) {
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

func typeToCaveat(t CaveatType) (Caveat, error) {
	cav, ok := t2c[t]
	if !ok {
		return nil, fmt.Errorf("unregistered caveat type %d", t)
	}

	ct := reflect.TypeOf(cav)
	if ct.Kind() == reflect.Pointer {
		return reflect.New(ct.Elem()).Interface().(Caveat), nil
	}
	return reflect.Zero(ct).Interface().(Caveat), nil
}

func caveatTypeFromString(s string) CaveatType {
	if t, ok := s2t[s]; ok {
		return t
	}

	return CavUnregistered
}

func caveatTypeToString(t CaveatType) string {
	if s, ok := t2s[t]; ok {
		return s
	}
	return "[unregistered]"
}
