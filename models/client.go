package models

import "github.com/alkeyio/authkit/types"

// Client represents an OAuth2 client application. Implement this interface
// with your own data model (e.g. a database-backed struct) and pass instances
// to the grant flows via ClientManager.
type Client interface {
	// GetClientID returns the unique public identifier of the client.
	GetClientID() string

	// GetScopes returns the full set of scopes registered for this client.
	GetScopes() types.Scopes

	// GetAllowedScopes returns the subset of the requested scopes that this
	// client is permitted to use. Implementations should filter scopes against
	// the client's registered scope list.
	GetAllowedScopes(scopes types.Scopes) types.Scopes

	// GetDefaultRedirectURI returns the default redirect URI used when the
	// authorization request omits redirect_uri.
	GetDefaultRedirectURI() string

	// CheckRedirectURI reports whether redirectURI is registered for this client.
	CheckRedirectURI(redirectURI string) bool

	// CheckGrantType reports whether this client is permitted to use the given
	// grant type (e.g. "authorization_code", "refresh_token").
	CheckGrantType(gt types.GrantType) bool

	// CheckResponseType reports whether this client is permitted to use the
	// given response type (e.g. "code").
	CheckResponseType(rt types.ResponseType) bool

	// CheckTokenEndpointAuthMethod reports whether the client supports the
	// given authentication method at the specified endpoint.
	CheckTokenEndpointAuthMethod(method types.ClientAuthMethod, endpoint string) bool

	// CheckClientSecret verifies the provided secret against the client's
	// stored credential. Implementations must use a constant-time comparison
	// to prevent timing attacks.
	CheckClientSecret(secret string) bool

	// IsPublic reports whether this is a public client as defined in
	// RFC 6749 §2.1. Public clients are applications that cannot securely
	// store a client secret (e.g. native apps, single-page applications).
	// They authenticate at the token endpoint using auth method "none".
	IsPublic() bool
}
