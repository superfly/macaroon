package machinesapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
)

var (
	// ExternalURL is reachable from the public internet.
	ExternalURL, _ = url.Parse("https://api.machines.dev")

	// InternalURL is only reachable from machines running on Fly.io.
	InternalURL, _ = url.Parse("http://_api.internal:4280")

	DefaultClient = &Client{}
)

const (
	authenticatePath = "/v1/tokens/authenticate"
	authorizePath    = "/v1/tokens/authorize"
)

// Client is a client for the Machines API tokens API. It implements
// bundle.Verifier for token verification. It also allows for authorization
// checking by external clients.
type Client struct {
	HTTP            http.RoundTripper
	BaseURL         *url.URL
	setDefaultsOnce sync.Once
}

// Verify implements bundle.Verifier using the Fly.io Machines API.
func (v *Client) Verify(ctx context.Context, dissByPerm map[bundle.Macaroon][]bundle.Macaroon) map[bundle.Macaroon]bundle.VerificationResult {
	allMacs := make([]bundle.Macaroon, 0, len(dissByPerm)*2)
	for perm, diss := range dissByPerm {
		allMacs = append(allMacs, perm)
		allMacs = append(allMacs, diss...)
	}

	reqBody := verifyRequest{Header: bundle.String(allMacs...)}
	respBody := make([]*verifyResult, 0, len(dissByPerm))

	if err := v.post(ctx, authenticatePath, &reqBody, &respBody); err != nil {
		ret := make(map[bundle.Macaroon]bundle.VerificationResult, len(dissByPerm))

		for perm := range dissByPerm {
			ret[perm] = &bundle.FailedMacaroon{
				UnverifiedMacaroon: perm.Unverified(),
				Err:                err,
			}
		}

		return ret
	}

	ret := resultsVerifier(respBody).Verify(ctx, dissByPerm)

	// resultsVerifier deletes successfully verified tokens from dissByPerm, so
	// the remaining ones are failed.
	for perm := range dissByPerm {
		ret[perm] = &bundle.FailedMacaroon{
			UnverifiedMacaroon: perm.Unverified(),
			Err:                errors.New("verification failed"),
		}
	}

	return ret
}

// The Machines API takes a different Access than is used in the flyio package.
// Most macaroon consumers don't know about numeric IDs or what apps belong to
// which orgs, etc, without making a bunch of extra API calls. The Machines API
// does this work for us.
//
// Access describes an attempt to access a resource. Resources are hierarchical
// it is necessary to specify parents of the resource being accessed. For
// example, if you specify a machine feature, you must also specify the machine
// that the feature belongs to. This is not necessary for the Org->App,
// App->Volume, or App->Machine relationships because the Machines API can
// figure those out itself. Multiple resources at the same level of hierarchy
// cannot be specified (e.g. can't specify Machine and Volume). The hierarchy is
// as follows:
//
//	-> Organization
//	  -> OrgFeature
//	  -> StorageObject
//	  -> App
//	    -> AppFeature
//	    -> Volume
//	    -> Machine
//	      -> MachineFeature
//	      -> Command
//
// Other fields on this struct are contextual, falling outside of this
// hierarchy. For example, the SourceMachine field specifies which fly.io
// machine is attempting the access, allowing caveats to restrict access to
// individual machines.
type Access struct {
	////
	// fields that need to be resolved and checked for consistency (e.g. right
	// org for given app)

	// OrgSlug is the slug of the organization being accessed.
	OrgSlug *string `json:"org_slug,omitempty"`

	// AppName is the name of the app being accessed.
	AppName *string `json:"app_name,omitempty"`

	// VolumeID is the encoded ID of the volume being accessed (e.g.
	// vol_r1p6pln1k9m9j7zr).
	VolumeID *string `json:"volume_id,omitempty"`

	// MachineID is the ID of the machine being accessed (e.g. 7811701f564258).
	MachineID *string `json:"machine_id,omitempty"`

	////
	// fields copied into flyio.Access verbatim

	// Action is the action being taken on the specified resource. This is the
	// combination of individual action characters (e.g "rw")
	//   - r: read
	//   - w: write
	//   - c: create
	//   - d: delete
	//   - C: control
	Action resset.Action `json:"action,omitempty"`

	// OrgFeature is a named set of functionality associated with the
	// organization. If this is specified, the OrgSlug field must be set.
	//   - wg: WireGuard peers
	//   - builder: remote builders
	//   - addon: addons
	//   - membership: organization membership
	//   - billing: billing
	//   - litefs-cloud: LiteFS Cloud
	//   - authentication: authentication settings
	OrgFeature *string `json:"org_feature,omitempty"`

	// AppFeature is a named set of functionality associated with the app. If
	// this is specified, the AppName field must be set.
	//   - images: images in the fly.io registry
	AppFeature *string `json:"app_feature,omitempty"`

	// MachineFeature is a named set of functionality associated with the
	// machine. If this is specified, the Machine field must be set.
	//   - metadata: machine metadata service
	//   - oidc: OIDC tokens
	MachineFeature *string `json:"machine_feature,omitempty"`

	// Mutation is the GraphQL mutation being performed.
	Mutation *string `json:"mutation,omitempty"`

	// SourceMachine is the machine ID of the actor attempting access.
	SourceMachine *string `json:"source_machine,omitempty"`

	// Command is the command being executed on a machine. If this is specified,
	// the Machine must be set.
	Command []string `json:"command,omitempty"`

	// StorageObject is the storage object being accessed. If this is specified,
	// the OrgSlug must be set.
	StorageObject *resset.Prefix `json:"storage_object,omitempty"`
}

// Authorize checks if the tokens in the provided header are authorized for the
// provided access. It returns the flyio.Access object that was authorized.
func (c *Client) Authorize(ctx context.Context, header string, access *Access) (*flyio.Access, error) {
	bun, err := flyio.ParseBundle(header)
	if err != nil {
		return nil, err
	}

	return c.AuthorizeBundle(ctx, bun, access)
}

// AuthorizeBundle is the same as Authorize, but works on an already parsed Bundle of tokens.
func (c *Client) AuthorizeBundle(ctx context.Context, bun *bundle.Bundle, access *Access) (*flyio.Access, error) {
	reqBody := authorizeRequest{Header: bun.String(), Access: access}
	respBody := authorizeResponse{}

	if err := c.post(ctx, authorizePath, &reqBody, &respBody); err != nil {
		return nil, err
	}

	// mark the authorized token as verified too
	if _, err := bun.Verify(ctx, resultsVerifier{respBody.VerifiedToken}); err != nil {
		return nil, err
	}

	return respBody.Access, nil
}

type authorizeRequest struct {
	Header string  `json:"header"`
	Access *Access `json:"access"`
}

type authorizeResponse struct {
	Access        *flyio.Access `json:"access"`
	VerifiedToken *verifyResult `json:"verified_token"`
}

type verifyRequest struct {
	Header string `json:"header"`
}

type verifyResult struct {
	Caveats         *macaroon.CaveatSet `json:"caveats"`
	PermissionToken []byte              `json:"permission_token"`
}

func (c *Client) post(ctx context.Context, path string, req any, resp any) error {
	c.setDefaultsOnce.Do(func() {
		if c.HTTP == nil {
			c.HTTP = cleanhttp.DefaultTransport()
		}

		if c.BaseURL == nil {
			if os.Getenv("FLY_APP_NAME") == "" {
				c.BaseURL = ExternalURL
			} else {
				c.BaseURL = InternalURL
			}
		}
	})

	if c.BaseURL == nil || c.HTTP == nil {
		return errors.New("invalid client")
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL.JoinPath(path).String(),
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpResp, err := c.HTTP.RoundTrip(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer httpResp.Body.Close()

	serverError := &ServerError{StatusCode: httpResp.StatusCode}
	target := resp

	if httpResp.StatusCode != http.StatusOK {
		target = serverError
	}

	if err := json.NewDecoder(httpResp.Body).Decode(target); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return serverError
	}

	return nil
}

// ServerError is an error returned by the Machines API server.
type ServerError struct {
	Err        string `json:"error"`
	StatusCode int    `json:"-"`
}

func (e *ServerError) Error() string {
	return e.Err
}

type resultsVerifier []*verifyResult

func (rv resultsVerifier) Verify(ctx context.Context, dissByPerm map[bundle.Macaroon][]bundle.Macaroon) map[bundle.Macaroon]bundle.VerificationResult {
	ret := make(map[bundle.Macaroon]bundle.VerificationResult, len(dissByPerm))

	permByTok := make(map[string]bundle.Macaroon, len(dissByPerm))
	for perm := range dissByPerm {
		toks, err := macaroon.Parse(perm.String())
		switch {
		case err != nil:
			delete(dissByPerm, perm)
			ret[perm] = &bundle.FailedMacaroon{
				UnverifiedMacaroon: perm.Unverified(),
				Err:                err,
			}
		case len(toks) != 1:
			delete(dissByPerm, perm)
			ret[perm] = &bundle.FailedMacaroon{
				UnverifiedMacaroon: perm.Unverified(),
				Err:                errors.New("bad token in bundle"),
			}
		}

		permByTok[string(toks[0])] = perm
	}

	for _, resp := range rv {
		perm, ok := permByTok[string(resp.PermissionToken)]
		if !ok {
			continue
		}

		delete(dissByPerm, perm)
		ret[perm] = &bundle.VerifiedMacaroon{
			UnverifiedMacaroon: perm.Unverified(),
			Caveats:            resp.Caveats,
		}
	}

	return ret
}
