package macaroon

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	AuthorizationSchemeFlyV1  = "FlyV1"
	authorizationSchemeBearer = "Bearer"
	permissionTokenLabel      = "fm1r"
	dischargeTokenLabel       = "fm1a"
	v2TokenLabel              = "fm2"
	oauthTokenLabel           = "fo1"
)

// Parses an Authorization header into its constituent tokens.
func Parse(header string) ([][]byte, error) {
	header, _ = StripAuthorizationScheme(header)
	strToks := strings.Split(header, ",")
	toks := make([][]byte, 0, len(strToks))

tokLoop:
	for _, tok := range strToks {
		pfx, b64, found := strings.Cut(tok, "_")
		if !found {
			return nil, fmt.Errorf("parse flyv1 token: malformed: %w", ErrUnrecognizedToken)
		}

		switch pfx {
		case permissionTokenLabel, dischargeTokenLabel, v2TokenLabel:
		case oauthTokenLabel:
			continue tokLoop
		default:
			return nil, fmt.Errorf("parse token: invalid token prefix '%s': %w", pfx, ErrUnrecognizedToken)
		}

		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("parse flyv1 token: %s: %s: %w", pfx, err, ErrUnrecognizedToken)
		}

		if len(raw) == 0 {
			return nil, fmt.Errorf("parse flyv1 token: blank %s: %w", pfx, ErrUnrecognizedToken)
		}

		toks = append(toks, raw)
	}

	if len(toks) == 0 {
		return nil, fmt.Errorf("parse tokens: no valid tokens found: %w", ErrUnrecognizedToken)
	}

	return toks, nil
}

// Parse a string token and find the contained permission token for the given location.
func ParsePermissionAndDischargeTokens(header string, location string) ([]byte, [][]byte, error) {
	tokens, err := Parse(header)
	if err != nil {
		return nil, nil, err
	}

	_, permissionTokens, _, dischargeTokens, err := FindPermissionAndDischargeTokens(tokens, location)
	switch {
	case err != nil:
		return nil, nil, err
	case len(permissionTokens) == 0:
		return nil, nil, errors.New("no permission token")
	case len(permissionTokens) > 1:
		return nil, nil, errors.New("multiple permission tokens")
	}

	return permissionTokens[0], dischargeTokens, err
}

func FindPermissionAndDischargeTokens(tokens [][]byte, location string) ([]*Macaroon, [][]byte, []*Macaroon, [][]byte, error) {
	var (
		permissionMacaroons []*Macaroon
		permissionTokens    [][]byte
		dischargeTokens     [][]byte
		dischargeMacaroons  []*Macaroon
	)

	for _, token := range tokens {
		if m, err := Decode(token); err == nil && m.Location == location {
			permissionMacaroons = append(permissionMacaroons, m)
			permissionTokens = append(permissionTokens, token)
		} else if err == nil {
			dischargeTokens = append(dischargeTokens, token)
			dischargeMacaroons = append(dischargeMacaroons, m)
		}
	}

	return permissionMacaroons, permissionTokens, dischargeMacaroons, dischargeTokens, nil
}

// ToAuthorizationHeader formats a collection of tokens as an HTTP
// Authorization header.
func ToAuthorizationHeader(toks ...[]byte) string {
	return AuthorizationSchemeFlyV1 + " " + encodeTokens(toks...)
}

func encodeTokens(toks ...[]byte) string {
	ret := ""
	for i, tok := range toks {
		if i > 0 {
			ret += ","
		}
		ret += fmt.Sprintf("%s_%s", v2TokenLabel, base64.StdEncoding.EncodeToString(tok))
	}

	return ret
}

// stripAuthorizationScheme strips any FlyV1/Bearer schemes from token header.
func StripAuthorizationScheme(hdr string) (string, bool) {
	hdr = strings.TrimSpace(hdr)

	pfx, rest, found := strings.Cut(hdr, " ")
	if !found {
		return hdr, false
	}

	switch pfx = strings.TrimSpace(pfx); {
	case strings.EqualFold(pfx, authorizationSchemeBearer), strings.EqualFold(pfx, AuthorizationSchemeFlyV1):
		hdr, _ = StripAuthorizationScheme(rest)
		return hdr, true
	default:
		return hdr, false
	}
}
