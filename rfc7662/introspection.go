package rfc7662

import (
	"net/http"
	"time"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/utils"
)

// TokenIntrospectionFlow implements RFC 7662 token introspection. It is
// registered as an endpoint on the server via Server.RegisterEndpoint and
// dispatched by Server.EndpointResponse when the endpoint name matches.
type TokenIntrospectionFlow struct {
	*Config
}

// NewTokenIntrospectionFlow creates a TokenIntrospectionFlow from cfg without
// validating it. Prefer MustTokenIntrospectionFlow for production use.
func NewTokenIntrospectionFlow(cfg *Config) *TokenIntrospectionFlow {
	return &TokenIntrospectionFlow{cfg}
}

// MustTokenIntrospectionFlow creates a TokenIntrospectionFlow after validating
// cfg. Returns an error if any required configuration is missing.
func MustTokenIntrospectionFlow(cfg *Config) (*TokenIntrospectionFlow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return NewTokenIntrospectionFlow(cfg), nil
}

// CheckEndpoint reports whether name matches the configured endpoint name.
// The server calls this to route requests to the correct registered endpoint.
func (f *TokenIntrospectionFlow) CheckEndpoint(name string) bool {
	if f.endpointName == "" {
		return false
	}

	return name == f.endpointName
}

// EndpointResponse handles an introspection request. It authenticates the
// caller, looks up the token, checks client permission, and writes the JSON
// introspection payload (RFC 7662 §2.2) to rw.
func (f *TokenIntrospectionFlow) EndpointResponse(r *http.Request, rw http.ResponseWriter) error {
	client, err := f.clientManager.Authenticate(r.Context(), r, f.supportedClientAuthMethods, f.endpointName)
	if err != nil {
		return autherrors.ToAuthKitError(err)
	}

	if utils.IsNil(client) {
		return autherrors.InvalidClientError()
	}

	req := NewRequestFromHTTP(r)
	req.Client = client

	if err = f.authenticateToken(req); err != nil {
		return err
	}

	payload := f.introspectionPayload(req)
	return utils.JSONResponse(rw, payload, http.StatusOK)
}

// authenticateToken validates request parameters, looks up the token, and
// verifies that the calling client has permission to introspect it.
func (f *TokenIntrospectionFlow) authenticateToken(r *Request) error {
	if err := f.checkParams(r); err != nil {
		return err
	}

	token, err := f.tokenManager.QueryByToken(r.Request.Context(), r.Token, r.TokenTypeHint)
	if err != nil {
		return err
	}

	if allowed := f.clientManager.CheckPermission(r.Request.Context(), r.Client, token, r.Request); !allowed {
		return autherrors.AccessDeniedError().WithDescription("client does not have permission to inspect token")
	}

	r.Tok = token
	return nil
}

// checkParams validates HTTP method, content type, and token presence per
// RFC 7662 §2.1. The token_type_hint is passed through as-is — unknown values
// are silently ignored per RFC 7662 §2.1 ("MAY ignore the hint").
func (f *TokenIntrospectionFlow) checkParams(r *Request) error {
	if err := r.ValidateHTTPMethod(); err != nil {
		return err
	}

	if err := r.ValidateContentType(); err != nil {
		return err
	}

	if err := r.ValidateToken(); err != nil {
		return err
	}

	return nil
}

// introspectionPayload builds the RFC 7662 §2.2 response payload. Returns
// {"active": false} when the token is not found or has expired. Otherwise,
// delegates to TokenManager.Inspect for the full claim set and sets active=true.
func (f *TokenIntrospectionFlow) introspectionPayload(r *Request) map[string]interface{} {
	inactive := map[string]interface{}{"active": false}

	if utils.IsNil(r.Tok) {
		return inactive
	}

	if r.Tok.GetIssuedAt().Add(r.Tok.GetAccessTokenExpiresIn()).Before(time.Now().UTC().Round(time.Second)) {
		return inactive
	}

	payload := f.tokenManager.Inspect(r.Request.Context(), r.Client, r.Tok)
	if payload == nil {
		payload = make(map[string]interface{})
	}

	payload["active"] = true
	return payload
}
