package ropc

import (
	"errors"
	"fmt"
	"net/http"

	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/rfc6749"
	"github.com/tniah/authkit/types"
	"github.com/tniah/authkit/utils"
)

const EndpointToken = "token"

var ErrNilToken = errors.New("token is nil")

// Flow implements the Resource Owner Password Credentials grant (RFC 6749 §4.3).
// It authenticates both the client and the end-user on a single /token request.
// NOTE: ROPC is a legacy grant; prefer Authorization Code + PKCE for new integrations.
type Flow struct {
	*Config
	*rfc6749.TokenFlowMixin
}

// New creates a Flow without validating config. Use Must for production use.
func New(cfg *Config) *Flow {
	return &Flow{Config: cfg, TokenFlowMixin: &rfc6749.TokenFlowMixin{}}
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
	return gt.IsROPC()
}

// ValidateTokenRequest validates the /token request: HTTP method, grant_type,
// username, password, client authentication, scope, and any registered
// TokenRequestValidator extensions.
func (f *Flow) ValidateTokenRequest(r *requests.TokenRequest) error {
	if err := f.checkParams(r); err != nil {
		return err
	}

	if err := f.authenticateClient(r); err != nil {
		return err
	}

	if err := f.validateScope(r); err != nil {
		return err
	}

	if err := f.authenticateUser(r); err != nil {
		return err
	}

	for _, h := range f.tokenReqValidators {
		if err := h.ValidateTokenRequest(r); err != nil {
			return err
		}
	}

	return nil
}

// TokenResponse generates the access token, runs TokenProcessor extensions,
// saves the token, and writes the JSON response (RFC 6749 §4.3.3 / §5.1).
func (f *Flow) TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error {
	token, err := f.genToken(r)
	if err != nil {
		return err
	}

	data := f.StandardTokenData(token)
	for _, h := range f.tokenProcessors {
		if err = h.ProcessToken(r, token, data); err != nil {
			return err
		}
	}

	if err = f.tokenMgr.Save(r.Request.Context(), token); err != nil {
		return err
	}

	return f.HandleTokenResponse(rw, data)
}

// checkParams validates the HTTP method, grant_type, username, and password
// before any manager calls are made.
func (f *Flow) checkParams(r *requests.TokenRequest) error {
	if err := f.checkTokenEndpointHttpMethod(r); err != nil {
		return err
	}

	if err := f.validateGrantType(r); err != nil {
		return err
	}

	if err := r.CheckUsername(); err != nil {
		return err
	}

	if err := r.CheckPassword(); err != nil {
		return err
	}

	return nil
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

// validateGrantType checks that grant_type is present and equals "password".
func (f *Flow) validateGrantType(r *requests.TokenRequest) error {
	if err := r.CheckGrantType(); err != nil {
		return err
	}

	if valid := r.GrantType.IsROPC(); !valid {
		return autherrors.UnsupportedGrantTypeError()
	}

	return nil
}

// authenticateClient delegates to ClientManager.Authenticate, then verifies the
// client is permitted to use the password grant. Returns unauthorized_client if
// the grant type is not enabled.
func (f *Flow) authenticateClient(r *requests.TokenRequest) error {
	client, err := f.clientMgr.Authenticate(r.Request, f.supportedClientAuthMethods, EndpointToken)
	if err != nil {
		return err
	}

	if utils.IsNil(client) {
		return autherrors.InvalidClientError()
	}

	// Verify the client is explicitly permitted to use the password grant.
	if allowed := client.CheckGrantType(types.GrantTypeROPC); !allowed {
		return autherrors.UnauthorizedClientError().WithDescription("The client is not authorized to use grant type \"password\"")
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

// authenticateUser delegates to UserManager.Authenticate. When the manager
// returns a nil user (credentials invalid), the flow responds with a generic
// invalid_grant message to avoid leaking whether the username exists
// (RFC 6749 §4.3.2). Errors from the manager are returned as-is; the
// UserManager implementation is responsible for not leaking internal details.
func (f *Flow) authenticateUser(r *requests.TokenRequest) error {
	user, err := f.userMgr.Authenticate(r.Username, r.Password, r.Client, r.Request)
	if err != nil {
		return err
	}

	if utils.IsNil(user) {
		// Return a generic message to avoid leaking whether the username exists.
		return autherrors.InvalidGrantError().WithDescription("Username or password is incorrect")
	}

	r.User = user
	return nil
}

// genToken allocates and populates a new token. A refresh token is included
// when the client has the refresh_token grant type registered.
func (f *Flow) genToken(r *requests.TokenRequest) (models.Token, error) {
	token := f.tokenMgr.New()
	if utils.IsNil(token) {
		return nil, ErrNilToken
	}

	// Include a refresh token only if the client has the refresh_token grant enabled.
	if err := f.tokenMgr.Generate(token, r, r.Client.CheckGrantType(types.GrantTypeRefreshToken)); err != nil {
		return nil, err
	}

	return token, nil
}
