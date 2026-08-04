package errors

import (
	"errors"
	"net/http"
)

const (
	ErrCode        = "error"
	ErrDescription = "error_description"
	ErrURI         = "error_uri"
	ErrState       = "state"
)

// OAuth 2.0 and OpenID Connect error code sentinels. Each value's Error()
// string is the wire-format error code sent in the JSON response body.
var (
	// ErrInvalidRequest is returned when the request is missing a required
	// parameter or is otherwise malformed (RFC 6749 §5.2).
	ErrInvalidRequest = errors.New("invalid_request")
	// ErrUnauthorizedClient is returned when the client is not authorised to
	// use the requested grant type (RFC 6749 §5.2).
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	// ErrAccessDenied is returned when the resource owner or authorization
	// server denies the request (RFC 6749 §4.1.2.1).
	ErrAccessDenied = errors.New("access_denied")
	// ErrUnsupportedResponseType is returned when the requested response_type
	// is not supported (RFC 6749 §4.1.2.1).
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	// ErrInvalidScope is returned when the requested scope is invalid, unknown,
	// or exceeds what the client may request (RFC 6749 §5.2).
	ErrInvalidScope = errors.New("invalid_scope")
	// ErrInvalidClient is returned when client authentication fails (RFC 6749 §5.2).
	// The response carries a 401 status and a WWW-Authenticate header.
	ErrInvalidClient = errors.New("invalid_client")
	// ErrInvalidGrant is returned when the authorization grant is invalid,
	// expired, revoked, or does not match the redirect URI (RFC 6749 §5.2).
	ErrInvalidGrant = errors.New("invalid_grant")
	// ErrUnsupportedGrantType is returned when the grant type is not supported
	// by the authorization server (RFC 6749 §5.2).
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
	// ErrUnsupportedTokenType is returned when the server does not support
	// revocation or introspection of the submitted token type (RFC 7662).
	ErrUnsupportedTokenType = errors.New("unsupported_token_type")
	// ErrServerError is returned when the server encounters an unexpected
	// condition that prevents it from fulfilling the request (RFC 6749 §5.2).
	ErrServerError = errors.New("server_error")
	// ErrTemporarilyUnavailable is returned when the server is temporarily
	// unable to handle the request (RFC 6749 §5.2).
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")
	// ErrLoginRequired is returned when the authorization server requires
	// end-user authentication but prompt=none was requested (OpenID Connect Core).
	ErrLoginRequired = errors.New("login_required")
	// ErrConsentRequired is returned when the authorization server requires
	// end-user consent but prompt=none was requested (OpenID Connect Core).
	ErrConsentRequired = errors.New("consent_required")
	// ErrAccountSelectionRequired is returned when the end-user must select a
	// session but prompt=none was requested (OpenID Connect Core).
	ErrAccountSelectionRequired = errors.New("account_selection_required")
)

// Descriptions maps each OAuth 2.0 error code to its default human-readable
// description. Used by NewOAuth2Error when no explicit description is provided.
var Descriptions = map[error]string{
	ErrInvalidRequest:           "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
	ErrUnauthorizedClient:       "The client is not authorized to request an authorization code using this method",
	ErrAccessDenied:             "The resource owner or authorization server denied the request",
	ErrUnsupportedResponseType:  "The authorization server does not support obtaining an authorization code using this method",
	ErrInvalidScope:             "The requested scope is invalid, unknown, or malformed",
	ErrInvalidClient:            "Client authentication failed",
	ErrInvalidGrant:             "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
	ErrUnsupportedGrantType:     "The authorization grant type is not supported by the authorization server",
	ErrUnsupportedTokenType:     "The authorization token type is not supported by the authorization server",
	ErrServerError:              "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
	ErrTemporarilyUnavailable:   "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server",
	ErrLoginRequired:            "The authorization server requires end-user authentication. This error may be returned when the prompt parameter value in the authentication request is none, but the authentication request cannot be completed without displaying a user interface for end-user authentication",
	ErrConsentRequired:          "The authorization server requires end-user consent. This error may be returned when the prompt parameter value in the authentication Request is none, but the authentication request cannot be completed without displaying a user interface for end-User consent",
	ErrAccountSelectionRequired: "The end-user is required to select a session at the Authorization Server.",
}

// HttpCodes maps each OAuth 2.0 error code to its HTTP status code.
// Looked up by NewOAuth2Error; unknown codes default to 400 Bad Request.
var HttpCodes = map[error]int{
	ErrInvalidRequest:           http.StatusBadRequest,
	ErrUnauthorizedClient:       http.StatusBadRequest,
	ErrAccessDenied:             http.StatusForbidden,
	ErrUnsupportedResponseType:  http.StatusBadRequest,
	ErrInvalidScope:             http.StatusBadRequest,
	ErrInvalidClient:            http.StatusUnauthorized,
	ErrInvalidGrant:             http.StatusBadRequest,
	ErrUnsupportedGrantType:     http.StatusBadRequest,
	ErrUnsupportedTokenType:     http.StatusForbidden,
	ErrServerError:              http.StatusInternalServerError,
	ErrTemporarilyUnavailable:   http.StatusServiceUnavailable,
	ErrLoginRequired:            http.StatusUnauthorized,
	ErrConsentRequired:          http.StatusForbidden,
	ErrAccountSelectionRequired: http.StatusForbidden,
}
