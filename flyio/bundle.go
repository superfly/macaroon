package flyio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/resset"
)

var (
	IsPermissionToken = bundle.LocationFilter(LocationPermission).Predicate()
	IsAuthToken       = bundle.LocationFilter(LocationAuthentication).Predicate()
	IsNewAuthToken    = bundle.LocationFilter(LocationNewAuthentication).Predicate()
	IsSecretsToken    = bundle.LocationFilter(LocationSecrets).Predicate()
)

// IsForOrgUnverified returns a Predicate, checking that the token is scoped to
// the given organization. Because this operates on unverified tokens, it
// doesn't imply any level of access to the org or that the selected tokens are
// valid.
func IsForOrgUnverified(oid uint64) bundle.Predicate {
	return bundle.MacaroonPredicate(func(t bundle.Macaroon) bool {
		if !IsPermissionToken(t) {
			return false
		}

		os, err := OrganizationScope(t.UnsafeCaveats())
		return err == nil && os == oid
	})
}

// IsForOrg returns a Predicate, checking that the token is scoped to the given
// organization. This doesn't imply any specific level of access to the
// organization.
func IsForOrg(orgID uint64) bundle.Predicate {
	return bundle.AllowsAccess(&Access{
		OrgID:  &orgID,
		Action: resset.ActionNone,
	})
}

func ParseBundle(hdr string) (*bundle.Bundle, error) {
	return bundle.ParseBundle(LocationPermission, hdr)
}

func ParseBundleWithFilter(hdr string, filter bundle.Filter) (*bundle.Bundle, error) {
	return bundle.ParseBundleWithFilter(LocationPermission, hdr, filter)
}

// MachinesAPIVerifier is a bundle.Verifier that uses the Machines API to verify
// macaroons.
type MachinesAPIVerifier struct {
	HTTP            http.RoundTripper
	URL             string
	setDefaultsOnce sync.Once
}

var (
	MachinesAPI                = "https://api.machines.dev"
	DefaultMachinesAPIVerifier = bundle.NewVerificationCache(&MachinesAPIVerifier{}, time.Minute, 1000)
)

func init() {
	if os.Getenv("FLY_APP_NAME") != "" {
		MachinesAPI = "http://_api.internal:4280"
	}
}

func (v *MachinesAPIVerifier) Verify(ctx context.Context, dissByPerm map[bundle.Macaroon][]bundle.Macaroon) map[bundle.Macaroon]bundle.VerificationResult {
	ret := make(map[bundle.Macaroon]bundle.VerificationResult, len(dissByPerm))

	failAll := func(err error) map[bundle.Macaroon]bundle.VerificationResult {
		for perm := range dissByPerm {
			ret[perm] = &bundle.FailedMacaroon{
				UnverifiedMacaroon: perm.Unverified(),
				Err:                err,
			}
		}

		return ret
	}

	v.setDefaultsOnce.Do(func() {
		if v.HTTP == nil {
			v.HTTP = http.DefaultTransport
		}

		if v.URL == "" {
			if u, err := url.JoinPath(MachinesAPI, "/v1/tokens/authenticate"); err == nil {
				v.URL = u
			}
		}
	})

	if v.URL == "" || v.HTTP == nil {
		return failAll(errors.New("invalid verifier"))
	}

	allMacs := make([]bundle.Macaroon, 0, len(dissByPerm)*2)
	for perm, diss := range dissByPerm {
		allMacs = append(allMacs, perm)
		allMacs = append(allMacs, diss...)
	}

	reqBody, err := json.Marshal(machinesVerificationRequest{
		Header: bundle.String(allMacs...),
	})
	if err != nil {
		return failAll(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.URL, bytes.NewReader(reqBody))
	if err != nil {
		return failAll(err)
	}

	resp, err := v.HTTP.RoundTrip(req)
	if err != nil {
		return failAll(err)
	}
	defer resp.Body.Close()

	respBody := make([]machinesVerificationResult, 0, len(dissByPerm))
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return failAll(err)
	}

	permByTok := make(map[string]bundle.Macaroon, len(dissByPerm))
	for perm, _ := range dissByPerm {
		encoded, err := perm.UnsafeMacaroon().Encode()
		if err != nil {
			return failAll(err)
		}

		permByTok[string(encoded)] = perm
	}

	for _, resp := range respBody {
		perm, ok := permByTok[string(resp.PermissionToken)]
		if !ok {
			continue
		}

		ret[perm] = &bundle.VerifiedMacaroon{
			UnverifiedMacaroon: perm.Unverified(),
			Caveats:            resp.Caveats,
		}

		// delete the perm so we can failAll the rest
		delete(dissByPerm, perm)
	}

	return failAll(errors.New("verification failed"))
}

type machinesVerificationRequest struct {
	Header string `json:"header"`
}

type machinesVerificationResult struct {
	Caveats         *macaroon.CaveatSet `json:"caveats"`
	PermissionToken []byte              `json:"permission_token"`
}
