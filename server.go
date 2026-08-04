package authkit

import (
	"encoding/json"
	"fmt"
	"net/http"

	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/utils"
)

// Server is the central OAuth2 coordinator. It dispatches incoming HTTP
// requests to the appropriate grant flow or endpoint based on response_type
// or grant_type. Flows and endpoints must be registered before handling requests.
type Server struct {
	// Slices preserve registration order, ensuring deterministic dispatch
	// when iterating to find a matching grant/endpoint.
	authorizationGrants []AuthorizationGrant
	consentGrants       []ConsentGrant
	tokenGrants         []TokenGrant
	endpoints           []Endpoint
	// errHandler, if set, overrides the default OAuth2 error response logic.
	errHandler ErrorHandler
}

// NewServer creates an empty Server. Register grants and endpoints before use.
func NewServer() *Server {
	return &Server{}
}

// AuthorizationGrant returns the first registered grant that supports the
// requested response_type, or UnsupportedResponseTypeError if none match.
func (srv *Server) AuthorizationGrant(r *requests.AuthorizationRequest) (AuthorizationGrant, error) {
	for _, grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

// ValidateAuthorizationRequest parses the HTTP request, sets the authenticated
// user, finds the matching AuthorizationGrant, and runs its validation step.
// It returns the grant and the populated request so the caller can proceed to
// issue the authorization response. Errors are returned unwrapped; use
// HandleError to convert them into HTTP responses.
func (srv *Server) ValidateAuthorizationRequest(hr *http.Request, u models.User) (AuthorizationGrant, *requests.AuthorizationRequest, error) {
	r, err := requests.NewAuthorizationRequestFromHttp(hr)
	if err != nil {
		return nil, nil, err
	}

	r.User = u

	grant, err := srv.AuthorizationGrant(r)
	if err != nil {
		return nil, nil, err
	}

	if err = grant.ValidateAuthorizationRequest(r); err != nil {
		return nil, nil, err
	}

	return grant, r, nil
}

// CreateAuthorizationResponse handles the /authorize endpoint. It parses the
// request, finds the matching grant, validates it, and writes the redirect response.
// u is the authenticated user populated into the request before validation;
// whether a nil user results in an error is determined by the grant flow.
func (srv *Server) CreateAuthorizationResponse(hr *http.Request, rw http.ResponseWriter, u models.User) error {
	grant, r, err := srv.ValidateAuthorizationRequest(hr, u)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.AuthorizationResponse(r, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

// ConsentGrant returns the first registered grant that supports the consent
// step for the requested response_type.
func (srv *Server) ConsentGrant(r *requests.AuthorizationRequest) (ConsentGrant, error) {
	for _, grant := range srv.consentGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

// ValidateConsentRequest parses the HTTP request, sets the authenticated user,
// finds the matching ConsentGrant, and runs its consent validation step.
// It returns the grant and the populated request so the caller can proceed to
// issue the authorization response. Errors are returned unwrapped; use
// HandleError to convert them into HTTP responses.
func (srv *Server) ValidateConsentRequest(hr *http.Request, u models.User) (ConsentGrant, *requests.AuthorizationRequest, error) {
	r, err := requests.NewAuthorizationRequestFromHttp(hr)
	if err != nil {
		return nil, nil, err
	}

	r.User = u

	grant, err := srv.ConsentGrant(r)
	if err != nil {
		return nil, nil, err
	}

	if err = grant.ValidateConsentRequest(r); err != nil {
		return nil, nil, err
	}

	return grant, r, nil
}

// CreateConsentResponse handles the consent page callback. It re-validates the
// authorization request after the user has approved (or denied) the consent screen.
func (srv *Server) CreateConsentResponse(hr *http.Request, rw http.ResponseWriter, u models.User) error {
	grant, r, err := srv.ValidateConsentRequest(hr, u)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.AuthorizationResponse(r, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

// TokenGrant returns the first registered grant that supports the requested
// grant_type, or UnsupportedGrantTypeError if none match.
func (srv *Server) TokenGrant(r *requests.TokenRequest) (TokenGrant, error) {
	for _, grant := range srv.tokenGrants {
		if grant.CheckGrantType(r.GrantType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedGrantTypeError()
}

// ValidateTokenRequest parses the HTTP request, finds the matching TokenGrant,
// and runs its validation step. It returns the grant and the populated request
// so the caller can proceed to issue the token response. Errors are returned
// unwrapped; use HandleError to convert them into HTTP responses.
func (srv *Server) ValidateTokenRequest(hr *http.Request) (TokenGrant, *requests.TokenRequest, error) {
	r := requests.NewTokenRequestFromHttp(hr)

	grant, err := srv.TokenGrant(r)
	if err != nil {
		return nil, nil, err
	}

	if err = grant.ValidateTokenRequest(r); err != nil {
		return nil, nil, err
	}

	return grant, r, nil
}

// CreateTokenResponse handles the /token endpoint. It parses the request,
// finds the matching grant, validates it, and writes the JSON token response.
func (srv *Server) CreateTokenResponse(hr *http.Request, rw http.ResponseWriter) error {
	grant, r, err := srv.ValidateTokenRequest(hr)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.TokenResponse(r, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

// Endpoint returns the registered endpoint matching the given name, or an
// error if no endpoint is found.
func (srv *Server) Endpoint(name string) (Endpoint, error) {
	for _, endpoint := range srv.endpoints {
		if endpoint.CheckEndpoint(name) {
			return endpoint, nil
		}
	}

	return nil, fmt.Errorf("no endpoint was found with \"%s\"", name)
}

// EndpointResponse dispatches an HTTP request to a named endpoint (e.g. "introspect").
func (srv *Server) EndpointResponse(hr *http.Request, rw http.ResponseWriter, name string) error {
	h, err := srv.Endpoint(name)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = h.EndpointResponse(hr, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

// RegisterGrant registers a grant flow for all applicable roles
// (AuthorizationGrant, ConsentGrant, TokenGrant) that it implements.
// A single flow struct may implement multiple interfaces simultaneously.
func (srv *Server) RegisterGrant(grant any) {
	srv.RegisterAuthorizationGrant(grant)
	srv.RegisterConsentGrant(grant)
	srv.RegisterTokenGrant(grant)
}

// RegisterAuthorizationGrant registers grant as an AuthorizationGrant if it
// implements the interface. Grants are matched in registration order.
func (srv *Server) RegisterAuthorizationGrant(grant any) {
	if g, ok := grant.(AuthorizationGrant); ok {
		srv.authorizationGrants = append(srv.authorizationGrants, g)
	}
}

// RegisterConsentGrant registers grant as a ConsentGrant if it implements
// the interface. Grants are matched in registration order.
func (srv *Server) RegisterConsentGrant(grant any) {
	if g, ok := grant.(ConsentGrant); ok {
		srv.consentGrants = append(srv.consentGrants, g)
	}
}

// RegisterTokenGrant registers grant as a TokenGrant if it implements the
// interface. Grants are matched in registration order.
func (srv *Server) RegisterTokenGrant(grant any) {
	if g, ok := grant.(TokenGrant); ok {
		srv.tokenGrants = append(srv.tokenGrants, g)
	}
}

// RegisterEndpoint registers an endpoint (e.g. token introspection) that can
// be dispatched to via EndpointResponse.
func (srv *Server) RegisterEndpoint(endpoint any) {
	if g, ok := endpoint.(Endpoint); ok {
		srv.endpoints = append(srv.endpoints, g)
	}
}

// RegisterErrorHandler sets a custom error handler. When set, all errors are
// forwarded to h instead of the default OAuth2 JSON/redirect response logic.
func (srv *Server) RegisterErrorHandler(h ErrorHandler) {
	srv.errHandler = h
}

// HandleError converts err to an OAuth2 error response. If a custom
// ErrorHandler is registered it takes full control. Otherwise:
//   - If err carries a RedirectURI, the client is redirected with the error params.
//   - Otherwise a JSON error body is written with the appropriate HTTP status.
//
// Non-AuthKitError values (e.g. unexpected DB errors) are wrapped in a 500
// InternalServerError automatically via ToAuthKitError.
func (srv *Server) HandleError(hr *http.Request, rw http.ResponseWriter, err error) error {
	if srv.errHandler != nil {
		return srv.errHandler(hr, rw, err)
	}

	authErr := autherrors.ToAuthKitError(err)

	if authErr.RedirectURI != "" {
		return utils.Redirect(rw, authErr.RedirectURI, authErr.Data())
	}

	status, header, data := authErr.Response()
	return srv.JSONResponse(rw, status, header, data)
}

// JSONResponse writes a JSON-encoded response with the given status code and
// optional extra headers. It also sets Content-Type: application/json.
func (srv *Server) JSONResponse(rw http.ResponseWriter, status int, header http.Header, data map[string]any) error {
	for k, v := range utils.JSONHeaders() {
		rw.Header().Set(k, v)
	}

	for k, v := range header {
		rw.Header()[k] = v
	}

	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(data)
}
