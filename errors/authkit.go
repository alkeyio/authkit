package errors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// AuthKitError extends OAuth2Error with authorization-server-specific context:
// an optional redirect URI (to send the client back after an error), an OAuth
// state value (echoed in the redirect), and the underlying cause for internal
// logging. It is the primary error type returned by all grant flows.
type AuthKitError struct {
	// State is the "state" parameter from the original authorization request.
	// When set it is included in the error redirect so the client can correlate
	// the response with its own state.
	State string

	// RedirectURI, when non-empty, causes HandleError to send a redirect
	// response instead of a JSON error body.
	RedirectURI string

	// Cause holds the original lower-level error (e.g. a store error or a
	// wrapped ErrInvalidClient). Used for internal logging; never sent to clients.
	Cause error

	*OAuth2Error
}

// NewAuthKitError creates an AuthKitError for the given RFC 6749 error code.
// The embedded OAuth2Error is initialised via NewOAuth2Error, which sets the
// HTTP status code and default description automatically.
func NewAuthKitError(code error) *AuthKitError {
	return &AuthKitError{
		OAuth2Error: NewOAuth2Error(code),
	}
}

// Data extends OAuth2Error.Data by appending the "state" field when present.
func (e *AuthKitError) Data() map[string]interface{} {
	data := e.OAuth2Error.Data()
	if e.State != "" {
		data[ErrState] = e.State
	}
	return data
}

// Response returns the HTTP status code, headers, and JSON body for the error
// response. For invalid_client (401), the WWW-Authenticate header is built at
// this point using the current Description so it always reflects the latest value
// set via WithDescription.
func (e *AuthKitError) Response() (statusCode int, header http.Header, data map[string]interface{}) {
	if errors.Is(e.Code, ErrInvalidClient) && e.HttpCode == http.StatusUnauthorized {
		errDesc := strings.ReplaceAll(e.Description, `"`, `\"`)
		challenge := fmt.Sprintf(`Basic error="%s", error_description="%s"`, e.Code, errDesc)
		e.SetHeader("WWW-Authenticate", challenge)
	}

	return e.HttpCode, e.HttpHeader, e.Data()
}

// WithDescription overrides the default error_description. Returns e for chaining.
func (e *AuthKitError) WithDescription(desc string) *AuthKitError {
	e.Description = desc
	return e
}

// WithErrorURI sets the optional error_uri field. Returns e for chaining.
func (e *AuthKitError) WithErrorURI(uri string) *AuthKitError {
	e.URI = uri
	return e
}

// WithState attaches the OAuth state parameter so it is echoed back in the
// error redirect. Returns e for chaining.
func (e *AuthKitError) WithState(state string) *AuthKitError {
	e.State = state
	return e
}

// WithRedirectURI sets the redirect destination for this error. When set,
// HandleError sends a redirect instead of a JSON body. Returns e for chaining.
func (e *AuthKitError) WithRedirectURI(redirectURI string) *AuthKitError {
	e.RedirectURI = redirectURI
	return e
}

// WithCause attaches the underlying error for internal diagnostics. The cause
// is never exposed to clients. Returns e for chaining.
func (e *AuthKitError) WithCause(err error) *AuthKitError {
	e.Cause = err
	return e
}

// ToAuthKitError unwraps err into an *AuthKitError using errors.As.
// If err is already an *AuthKitError it is returned as-is; otherwise an
// InternalServerError wrapping err as Cause is returned. Never returns nil.
func ToAuthKitError(err error) *AuthKitError {
	var authErr *AuthKitError

	if errors.As(err, &authErr) {
		return authErr
	}

	return InternalServerError().WithCause(err)
}

// InvalidRequestError returns a 400 error for a malformed or missing parameter
// in the request (RFC 6749 §5.2 "invalid_request").
func InvalidRequestError() *AuthKitError {
	return NewAuthKitError(ErrInvalidRequest)
}

// InvalidScopeError returns a 400 error when the requested scope is invalid,
// unknown, or exceeds what the client is permitted to request
// (RFC 6749 §5.2 "invalid_scope").
func InvalidScopeError() *AuthKitError {
	return NewAuthKitError(ErrInvalidScope)
}

// InvalidClientError returns a 401 error for failed client authentication —
// unknown client, wrong secret, or unsupported auth method (RFC 6749 §5.2 "invalid_client").
// The WWW-Authenticate header is built lazily in Response() so it always reflects
// the description at the time the response is written, including any value set
// via WithDescription.
func InvalidClientError() *AuthKitError {
	return NewAuthKitError(ErrInvalidClient)
}

// UnauthorizedClientError returns a 400 error when the authenticated client is
// not permitted to use the requested grant type (RFC 6749 §5.2 "unauthorized_client").
func UnauthorizedClientError() *AuthKitError {
	return NewAuthKitError(ErrUnauthorizedClient)
}

// InvalidGrantError returns a 400 error when the provided authorization grant
// (code, refresh token, credentials) is invalid, expired, or revoked
// (RFC 6749 §5.2 "invalid_grant").
func InvalidGrantError() *AuthKitError {
	return NewAuthKitError(ErrInvalidGrant)
}

// UnsupportedGrantTypeError returns a 400 error when the requested grant type
// is not supported by the authorization server (RFC 6749 §5.2 "unsupported_grant_type").
func UnsupportedGrantTypeError() *AuthKitError {
	return NewAuthKitError(ErrUnsupportedGrantType)
}

// UnsupportedResponseTypeError returns a 400 error when the requested
// response_type is not supported (RFC 6749 §4.1.2.1 "unsupported_response_type").
func UnsupportedResponseTypeError() *AuthKitError {
	return NewAuthKitError(ErrUnsupportedResponseType)
}

// AccessDeniedError returns a 403 error when the resource owner or authorization
// server explicitly denies the request (RFC 6749 §4.1.2.1 "access_denied").
func AccessDeniedError() *AuthKitError {
	return NewAuthKitError(ErrAccessDenied)
}

// UnsupportedTokenType returns a 403 error when the server does not support
// revocation or introspection of the submitted token type (RFC 7009 / RFC 7662
// "unsupported_token_type").
func UnsupportedTokenType() *AuthKitError {
	return NewAuthKitError(ErrUnsupportedTokenType)
}

// InternalServerError returns a 500 error for unexpected server-side failures
// (RFC 6749 §5.2 "server_error").
func InternalServerError() *AuthKitError {
	return NewAuthKitError(ErrServerError)
}

// LoginRequiredError returns a 401 error when the authorization server requires
// end-user authentication but the request asked for no UI (OIDC "login_required").
func LoginRequiredError() *AuthKitError {
	return NewAuthKitError(ErrLoginRequired)
}

// ConsentRequiredError returns a 403 error when the authorization server requires
// explicit end-user consent but the request asked for no UI (OIDC "consent_required").
func ConsentRequiredError() *AuthKitError {
	return NewAuthKitError(ErrConsentRequired)
}

// AccountSelectionRequiredError returns a 403 error when the end-user must
// select a session but the request asked for no UI (OIDC "account_selection_required").
func AccountSelectionRequiredError() *AuthKitError {
	return NewAuthKitError(ErrAccountSelectionRequired)
}
