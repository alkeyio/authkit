package authkit

import (
	"net/http"

	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/types"
)

// AuthorizationGrant handles the /authorize endpoint for a specific response_type.
// Implement this interface (along with ConsentGrant and/or TokenGrant) in a single
// flow struct, then register it with Server.RegisterGrant.
type AuthorizationGrant interface {
	// CheckResponseType reports whether this grant handles the given response_type.
	CheckResponseType(typ types.ResponseType) bool
	// ValidateAuthorizationRequest validates the incoming /authorize request,
	// including client lookup, redirect URI, scope, and any extension checks.
	ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
	// AuthorizationResponse issues the authorization response (e.g. redirects
	// the browser with a code or token).
	AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error
}

// ConsentGrant extends a flow with a dedicated consent validation step called
// after the user has confirmed or denied the consent screen.
type ConsentGrant interface {
	// CheckResponseType reports whether this grant handles the given response_type.
	CheckResponseType(typ types.ResponseType) bool
	// ValidateConsentRequest validates the request after the user acts on the
	// consent screen. Typically, checks session state and user approval.
	ValidateConsentRequest(r *requests.AuthorizationRequest) error
	// AuthorizationResponse issues the final authorization response once
	// consent has been validated.
	AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error
}

// TokenGrant handles the /token endpoint for a specific grant_type.
type TokenGrant interface {
	// CheckGrantType reports whether this grant handles the given grant_type.
	CheckGrantType(gt types.GrantType) bool
	// ValidateTokenRequest validates the /token request, including client
	// authentication, grant-specific parameters, and scope.
	ValidateTokenRequest(r *requests.TokenRequest) error
	// TokenResponse generates the access token and writes the JSON response
	// (RFC 6749 §5.1).
	TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error
}

// Endpoint handles auxiliary OAuth2 endpoints such as token introspection.
// Register with Server.RegisterEndpoint and dispatch via Server.EndpointResponse.
type Endpoint interface {
	// CheckEndpoint reports whether this handler owns the named endpoint.
	CheckEndpoint(name string) bool
	// EndpointResponse processes the request and writes the HTTP response.
	EndpointResponse(r *http.Request, rw http.ResponseWriter) error
}

// ErrorHandler is an optional custom function that takes over all error
// responses when registered via Server.RegisterErrorHandler. It must write
// its own HTTP response and return any secondary error.
type ErrorHandler func(hr *http.Request, rw http.ResponseWriter, err error) error
