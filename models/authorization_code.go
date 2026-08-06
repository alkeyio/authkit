package models

import (
	"time"

	"github.com/alkeyio/authkit/types"
)

// AuthorizationCodeReader provides read-only access to an authorization code.
// Use this interface in call sites that only need to inspect code fields
// (e.g. token processors, introspection, logging).
type AuthorizationCodeReader interface {
	GetCode() string
	GetClientID() string
	GetUserID() string
	GetRedirectURI() string
	GetResponseType() types.ResponseType
	GetScopes() types.Scopes
	GetNonce() string
	GetState() string
	GetAuthTime() time.Time
	GetExpiresIn() time.Duration
	GetCodeChallenge() string
	GetCodeChallengeMethod() types.CodeChallengeMethod
}

// AuthorizationCodeWriter provides write-only access to an authorization code.
// Use this interface in call sites that only need to populate code fields
// (e.g. code generators).
type AuthorizationCodeWriter interface {
	SetCode(code string)
	SetClientID(clientID string)
	SetUserID(userID string)
	SetRedirectURI(redirectURI string)
	SetResponseType(rt types.ResponseType)
	SetScopes(scopes types.Scopes)
	SetNonce(nonce string)
	SetState(state string)
	SetAuthTime(time.Time)
	SetExpiresIn(time.Duration)
	SetCodeChallenge(codeChallenge string)
	SetCodeChallengeMethod(method types.CodeChallengeMethod)
}

// AuthorizationCode represents an OAuth 2.0 authorization code issued at the
// authorization endpoint. Implement this interface with your own data model
// and pass instances through the authorization code grant flow.
//
// It composes AuthorizationCodeReader and AuthorizationCodeWriter so callers
// that only need read or write access can declare the narrower interface.
type AuthorizationCode interface {
	AuthorizationCodeReader
	AuthorizationCodeWriter
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
