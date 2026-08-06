package clientcredentials

import (
	"errors"
	"fmt"
	"net/http"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/rfc6749"
	"github.com/alkeyio/authkit/types"
	"github.com/alkeyio/authkit/utils"
)

// EndpointToken is the endpoint name passed to ClientManager.Authenticate so
// that the client store can apply per-endpoint auth method policies.
const EndpointToken = "token"

// ErrNilToken is returned by genToken when TokenManager.New returns nil.
var ErrNilToken = errors.New("token is nil")

// Flow implements the Client Credentials grant (RFC 6749 §4.4).
// Use Must or New to construct an instance from a Config.
type Flow struct {
	*Config
	*rfc6749.TokenFlowMixin
}

// New returns a Flow without validating the config. Prefer Must for production use.
func New(config *Config) *Flow {
	return &Flow{
		Config:         config,
		TokenFlowMixin: &rfc6749.TokenFlowMixin{},
	}
}

// Must returns a validated Flow or an error if the config is incomplete.
func Must(cfg *Config) (*Flow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

// CheckGrantType reports whether this flow handles the given grant_type.
func (f *Flow) CheckGrantType(gt types.GrantType) bool {
	return gt.IsClientCredentials()
}

// ValidateTokenRequest runs the full validation pipeline for an incoming token
// request: HTTP method → grant_type → client authentication → scope →
// registered extension validators. Returns the first error encountered.
func (f *Flow) ValidateTokenRequest(r *requests.TokenRequest) error {
	if err := f.checkTokenEndpointHttpMethod(r); err != nil {
		return err
	}

	if err := f.validateGrantType(r); err != nil {
		return err
	}

	if err := f.authenticateClient(r); err != nil {
		return err
	}

	if err := f.validateScope(r); err != nil {
		return err
	}

	for _, h := range f.tokenReqValidators {
		if err := h.ValidateTokenRequest(r.Request.Context(), r); err != nil {
			return err
		}
	}

	return nil
}

// TokenResponse generates an access token, runs registered token processors,
// persists the token, and writes the JSON response (RFC 6749 §5.1).
// No refresh token is ever included (RFC 6749 §4.4.3).
func (f *Flow) TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error {
	token, err := f.genToken(r)
	if err != nil {
		return err
	}

	data := f.StandardTokenData(token)
	for _, h := range f.tokenProcessors {
		if err = h.ProcessToken(r.Request.Context(), r, token, data); err != nil {
			return err
		}
	}

	if err = f.tokenMgr.Save(r.Request.Context(), token); err != nil {
		return err
	}

	return f.HandleTokenResponse(rw, data)
}

// checkTokenEndpointHttpMethod rejects requests whose HTTP method is not in
// tokenEndpointHttpMethods (default: POST).
func (f *Flow) checkTokenEndpointHttpMethod(r *requests.TokenRequest) error {
	for _, method := range f.tokenEndpointHttpMethods {
		if r.Method() == method {
			return nil
		}
	}

	return autherrors.InvalidRequestError().WithDescription(fmt.Sprintf("unsupported http method \"%s\"", r.Method()))
}

// validateGrantType checks that grant_type is present and equals "client_credentials".
func (f *Flow) validateGrantType(r *requests.TokenRequest) error {
	if err := r.CheckGrantType(); err != nil {
		return err
	}

	if valid := r.GrantType.IsClientCredentials(); !valid {
		return autherrors.UnsupportedGrantTypeError()
	}

	return nil
}

// authenticateClient delegates to ClientManager.Authenticate, then verifies the
// client is confidential and permitted to use the "client_credentials" grant.
func (f *Flow) authenticateClient(r *requests.TokenRequest) error {
	client, err := f.clientMgr.Authenticate(r.Request.Context(), r.Request, f.supportedClientAuthMethods, EndpointToken)
	if err != nil {
		return err
	}

	if utils.IsNil(client) {
		return autherrors.InvalidClientError()
	}

	// RFC 6749 §4.4: the client credentials grant MUST only be used by
	// confidential clients. Public clients cannot securely hold a secret and
	// therefore cannot prove their identity at this endpoint.
	if client.IsPublic() {
		return autherrors.InvalidClientError().WithDescription("client credentials grant is not allowed for public clients")
	}

	// Verify the client is explicitly permitted to use the client_credentials grant.
	if allowed := client.CheckGrantType(types.GrantTypeClientCredentials); !allowed {
		return autherrors.UnauthorizedClientError().WithDescription("the client is not authorized to use grant type \"client_credentials\"")
	}

	r.Client = client
	return nil
}

// validateScope filters the requested scopes through the client's allowed list.
// When the scope parameter is absent, the behavior is governed by
// Config.omittedScopePolicy (RFC 6749 §3.3):
//   - OmittedScopePolicyReject (default): reject with invalid_scope.
//   - OmittedScopePolicyUseClientDefault: grant the client's full registered scope list.
func (f *Flow) validateScope(r *requests.TokenRequest) error {
	if len(r.Scopes) == 0 {
		switch f.omittedScopePolicy {
		case OmittedScopePolicyUseClientDefault:
			r.Scopes = r.Client.GetScopes()
			return nil
		default:
			return autherrors.InvalidScopeError().WithDescription("scope is required")
		}
	}

	allowed := r.Client.GetAllowedScopes(r.Scopes)
	if len(allowed) == 0 {
		return autherrors.InvalidScopeError().WithDescription("none of the requested scopes are permitted for this client")
	}

	r.Scopes = allowed
	return nil
}

// genToken allocates and populates a new token.
// RFC 6749 §4.4.3: a refresh token SHOULD NOT be included in the client
// credentials grant — the client can re-authenticate at any time using its
// own credentials.
func (f *Flow) genToken(r *requests.TokenRequest) (models.Token, error) {
	token := f.tokenMgr.New()
	if utils.IsNil(token) {
		return nil, ErrNilToken
	}

	if err := f.tokenMgr.Generate(r.Request.Context(), token, r, false); err != nil {
		return nil, err
	}

	return token, nil
}
