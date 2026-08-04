package models

import (
	"time"

	"github.com/alkeyio/authkit/types"
)

// AuthorizationCode represents an OAuth 2.0 authorization code issued at the
// authorization endpoint. Implement this interface with your own data model
// and pass instances through the authorization code grant flow.
type AuthorizationCode interface {
	// GetCode / SetCode get and set the authorization code string.
	GetCode() string
	SetCode(code string)

	// GetClientID / SetClientID get and set the client the code was issued to.
	GetClientID() string
	SetClientID(clientID string)

	// GetUserID / SetUserID get and set the user who authorized the request.
	GetUserID() string
	SetUserID(userID string)

	// GetRedirectURI / SetRedirectURI get and set the redirect URI from the
	// authorization request. Must be verified again at the token endpoint.
	GetRedirectURI() string
	SetRedirectURI(redirectURI string)

	// GetResponseType / SetResponseType get and set the response_type from
	// the authorization request.
	GetResponseType() types.ResponseType
	SetResponseType(rt types.ResponseType)

	// GetScopes / SetScopes get and set the approved scopes.
	GetScopes() types.Scopes
	SetScopes(scopes types.Scopes)

	// GetNonce / SetNonce get and set the OIDC nonce value to be forwarded
	// to the ID token.
	GetNonce() string
	SetNonce(nonce string)

	// GetState / SetState get and set the state parameter echoed from the
	// authorization request.
	GetState() string
	SetState(state string)

	// GetAuthTime / SetAuthTime get and set the time the user authenticated.
	GetAuthTime() time.Time
	SetAuthTime(time.Time)

	// GetExpiresIn / SetExpiresIn get and set the code lifetime. The
	// authorization server MUST expire codes after a short period
	// (RFC 6749 §4.1.2 recommends a maximum of 10 minutes).
	GetExpiresIn() time.Duration
	SetExpiresIn(time.Duration)

	// GetCodeChallenge / SetCodeChallenge get and set the PKCE code challenge
	// (RFC 7636).
	GetCodeChallenge() string
	SetCodeChallenge(codeChallenge string)

	// GetCodeChallengeMethod / SetCodeChallengeMethod get and set the PKCE
	// challenge method ("plain" or "S256").
	GetCodeChallengeMethod() types.CodeChallengeMethod
	SetCodeChallengeMethod(method types.CodeChallengeMethod)
}

// ExtendableAuthorizationCode extends AuthorizationCode with an arbitrary
// key-value map for storing application-specific data alongside the standard
// code fields.
type ExtendableAuthorizationCode interface {
	AuthorizationCode

	// GetExtraData / SetExtraData get and set the additional data map.
	GetExtraData() map[string]interface{}
	SetExtraData(data map[string]interface{})
}
