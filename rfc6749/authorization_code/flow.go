package authorizationcode

import (
	"errors"
	"fmt"
	"net/http"
	"time"

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

var (
	ErrNilAuthCode = errors.New("authorization code is nil")
	ErrNilToken    = errors.New("token is nil")
)

// Flow implements the Authorization Code Grant (RFC 6749 §4.1).
// It satisfies the server.AuthorizationGrant, server.ConsentGrant, and
// server.TokenGrant interfaces, enabling registration with Server.RegisterGrant.
type Flow struct {
	*Config
	*rfc6749.TokenFlowMixin
}

// New creates a Flow from cfg without validating dependencies. Prefer Must for
// production use to catch missing managers at startup.
func New(cfg *Config) *Flow {
	return &Flow{Config: cfg, TokenFlowMixin: &rfc6749.TokenFlowMixin{}}
}

// Must returns a validated Flow or an error if any required Config dependency
// is missing. Use this in application startup to fail fast.
func Must(cfg *Config) (*Flow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

// CheckGrantType returns true for grant_type=authorization_code, used by the
// server dispatcher to route token requests to this flow.
func (f *Flow) CheckGrantType(gt types.GrantType) bool {
	return gt.IsAuthorizationCode()
}

// CheckResponseType returns true for response_type=code, used by the server
// dispatcher to route authorization requests to this flow.
func (f *Flow) CheckResponseType(typ types.ResponseType) bool {
	return typ.IsCode()
}

// ValidateAuthorizationRequest validates the incoming /authorize request:
// HTTP method, client_id, redirect_uri, response_type, and any registered
// AuthorizationRequestValidator extensions (e.g. PKCE, OIDC).
func (f *Flow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if err := f.checkAuthEndpointHttpMethod(r); err != nil {
		return err
	}

	if err := f.checkClient(r); err != nil {
		return err
	}

	if err := f.validateRedirectURI(r); err != nil {
		return err
	}

	if err := f.validateResponseType(r); err != nil {
		return err
	}

	if err := f.validateScope(r); err != nil {
		return err
	}

	r.GrantType = types.GrantTypeAuthorizationCode
	for _, h := range f.authReqValidators {
		if err := h.ValidateAuthorizationRequest(r); err != nil {
			return err
		}
	}

	return nil
}

// ValidateConsentRequest re-runs ValidateAuthorizationRequest and then invokes
// all registered ConsentRequestValidator extensions. Call this before rendering
// the consent screen to verify the request is still valid.
func (f *Flow) ValidateConsentRequest(r *requests.AuthorizationRequest) error {
	if err := f.ValidateAuthorizationRequest(r); err != nil {
		return err
	}

	for _, h := range f.consentReqValidators {
		if err := h.ValidateConsentRequest(r); err != nil {
			return err
		}
	}

	return nil
}

// AuthorizationResponse generates the authorization code, runs AuthCodeProcessor
// extensions, saves the code, and redirects the user-agent back to redirect_uri
// with code and state parameters (RFC 6749 §4.1.2).
// Returns access_denied if r.User is nil (i.e. the user did not authenticate).
func (f *Flow) AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error {
	if utils.IsNil(r.User) {
		return autherrors.AccessDeniedError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	authCode, err := f.genAuthCode(r)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		"code": authCode.GetCode(),
	}
	if r.State != "" {
		params["state"] = r.State
	}

	for _, h := range f.authCodeProcessors {
		if err = h.ProcessAuthorizationCode(r, authCode, params); err != nil {
			return err
		}
	}

	if err = f.authCodeMgr.Save(r.Request.Context(), authCode); err != nil {
		return err
	}

	return utils.Redirect(rw, r.RedirectURI, params)
}

// ValidateTokenRequest validates the /token request: HTTP method, grant_type,
// client authentication, authorization code validity, and any registered
// TokenRequestValidator extensions (e.g. PKCE code_verifier check).
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

	if err := f.validateAuthCode(r); err != nil {
		return err
	}

	for _, h := range f.tokenReqValidators {
		if err := h.ValidateTokenRequest(r); err != nil {
			return err
		}
	}

	return nil
}

// TokenResponse issues the access token
// (RFC 6749 §4.1.4 / §5.1).
func (f *Flow) TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error {
	if err := f.queryUserByAuthCode(r); err != nil {
		return err
	}

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

	if err = f.authCodeMgr.DeleteByCode(r.Request.Context(), r.AuthCode.GetCode()); err != nil {
		return err
	}

	if err = f.tokenMgr.Save(r.Request.Context(), token); err != nil {
		return err
	}

	return f.HandleTokenResponse(rw, data)
}

// checkAuthEndpointHttpMethod rejects requests whose HTTP method is not in
// authEndpointHttpMethods (default: GET).
func (f *Flow) checkAuthEndpointHttpMethod(r *requests.AuthorizationRequest) error {
	for _, method := range f.authEndpointHttpMethods {
		if r.Method() == method {
			return nil
		}
	}

	return autherrors.InvalidRequestError().WithDescription(fmt.Sprintf("unsupported http method \"%s\"", r.Method()))
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

// checkClient validates client_id and loads the client record into r.Client.
func (f *Flow) checkClient(r *requests.AuthorizationRequest) error {
	if err := r.CheckClientID(true); err != nil {
		return err
	}

	client, err := f.clientMgr.QueryByClientID(r.Request.Context(), r.ClientID)
	if err != nil {
		return err
	}

	if utils.IsNil(client) {
		return autherrors.InvalidRequestError().
			WithDescription("No client was found that matches \"client_id\" value").
			WithState(r.State)
	}

	r.Client = client
	return nil
}

// validateRedirectURI ensures redirect_uri is present and registered for the
// client. Falls back to the client's default redirect URI when omitted.
func (f *Flow) validateRedirectURI(r *requests.AuthorizationRequest) error {
	if r.RedirectURI == "" {
		r.RedirectURI = r.Client.GetDefaultRedirectURI()
		if r.RedirectURI == "" {
			return autherrors.InvalidRequestError().
				WithDescription("Missing \"redirect_uri\" in request").
				WithState(r.State)
		}

		return nil
	}

	if allowed := r.Client.CheckRedirectURI(r.RedirectURI); !allowed {
		return autherrors.InvalidRequestError().
			WithDescription("\"redirect_uri\" is not supported by client").
			WithState(r.State)
	}

	return nil
}

// validateResponseType verifies response_type=code and that the client is
// permitted to use this response type.
func (f *Flow) validateResponseType(r *requests.AuthorizationRequest) error {
	if err := r.CheckResponseType(true); err != nil {
		return err
	}

	if valid := r.ResponseType.IsCode(); !valid {
		return autherrors.UnsupportedResponseTypeError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	if allowed := r.Client.CheckResponseType(r.ResponseType); !allowed {
		return autherrors.UnauthorizedClientError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

// validateScope filters the requested scopes through the client's allowed list.
// When the scope parameter is absent, the behavior is governed by
// Config.omittedScopePolicy (RFC 6749 §3.3):
//   - OmittedScopePolicyReject (default): reject with invalid_scope.
//   - OmittedScopePolicyUseClientDefault: grant the client's full registered scope list.
func (f *Flow) validateScope(r *requests.AuthorizationRequest) error {
	if len(r.Scopes) == 0 {
		switch f.omittedScopePolicy {
		case OmittedScopePolicyUseClientDefault:
			r.Scopes = r.Client.GetScopes()
			return nil
		default:
			return autherrors.InvalidScopeError().
				WithDescription("scope is required").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}
	}

	allowed := r.Client.GetAllowedScopes(r.Scopes)
	if len(allowed) == 0 {
		return autherrors.InvalidScopeError().
			WithDescription("none of the requested scopes are permitted for this client").
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	r.Scopes = allowed
	return nil
}

// genAuthCode allocates and populates a new authorization code via AuthCodeManager.
func (f *Flow) genAuthCode(r *requests.AuthorizationRequest) (models.AuthorizationCode, error) {
	authCode := f.authCodeMgr.New()
	if utils.IsNil(authCode) {
		return nil, ErrNilAuthCode
	}

	if err := f.authCodeMgr.Generate(authCode, r); err != nil {
		return nil, err
	}

	return authCode, nil
}

// validateGrantType checks that grant_type is present and equals authorization_code.
func (f *Flow) validateGrantType(r *requests.TokenRequest) error {
	if err := r.CheckGrantType(); err != nil {
		return err
	}

	if valid := r.GrantType.IsAuthorizationCode(); !valid {
		return autherrors.UnsupportedGrantTypeError()
	}

	return nil
}

// authenticateClient delegates to ClientManager.Authenticate using the configured
// supported methods. Propagates any AuthKitError from the manager (e.g. one
// carrying a WWW-Authenticate header); wraps unexpected errors as server_error.
func (f *Flow) authenticateClient(r *requests.TokenRequest) error {
	cl, err := f.clientMgr.Authenticate(r.Request, f.supportedClientAuthMethods, EndpointToken)
	if err != nil {
		return err
	}

	if utils.IsNil(cl) {
		return autherrors.InvalidClientError()
	}

	r.Client = cl
	return nil
}

// validateAuthCode verifies the authorization code: existence, client binding,
// expiry, and redirect_uri match (RFC 6749 §4.1.3). Populates r.AuthCode on success.
func (f *Flow) validateAuthCode(r *requests.TokenRequest) error {
	if err := r.CheckCode(); err != nil {
		return err
	}

	authCode, err := f.authCodeMgr.QueryByCode(r.Request.Context(), r.Code)
	if err != nil {
		return err
	}

	if utils.IsNil(authCode) {
		return autherrors.InvalidGrantError().WithDescription("Invalid \"code\" in request")
	}

	// RFC 6749 §4.1.3: verify the code was issued to the authenticated client.
	if authCode.GetClientID() != r.Client.GetClientID() {
		return autherrors.InvalidGrantError().WithDescription("\"code\" was not issued to this client")
	}

	if authCode.GetAuthTime().Add(authCode.GetExpiresIn()).Before(time.Now().UTC().Round(time.Second)) {
		return autherrors.InvalidGrantError().WithDescription("\"code\" has been expired")
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.RedirectURI {
		return autherrors.InvalidGrantError().WithDescription("Invalid \"redirect_uri\" in request")
	}

	r.AuthCode = authCode
	return nil
}

// queryUserByAuthCode resolves the resource owner from the authorization code
// and populates r.User. Returns invalid_grant if no user is found.
func (f *Flow) queryUserByAuthCode(r *requests.TokenRequest) error {
	userID := r.AuthCode.GetUserID()
	if userID == "" {
		return autherrors.InvalidGrantError().WithDescription("No user could be found associated with this authorization code")
	}

	user, err := f.userMgr.QueryUserByCode(r.Request.Context(), r.AuthCode, r)
	if err != nil {
		return err
	}

	if utils.IsNil(user) {
		return autherrors.InvalidGrantError().WithDescription("No user could be found associated with this authorization code")
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

	r.Scopes = r.AuthCode.GetScopes()
	if err := f.tokenMgr.Generate(token, r, r.Client.CheckGrantType(types.GrantTypeRefreshToken)); err != nil {
		return nil, err
	}

	return token, nil
}
