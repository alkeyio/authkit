package models

import (
	"time"

	"github.com/alkeyio/authkit/types"
)

// TokenReader provides read-only access to a token.
// Use this interface in call sites that only need to inspect token fields
// (e.g. token processors, introspection, claim generation, logging).
type TokenReader interface {
	GetType() string
	GetAccessToken() string
	GetRefreshToken() string
	GetClientID() string
	GetScopes() types.Scopes
	GetIssuedAt() time.Time
	GetAccessTokenExpiresIn() time.Duration
	GetRefreshTokenExpiresIn() time.Duration
	GetUserID() string
	GetJwtID() string
}

// TokenWriter provides write-only access to a token.
// Use this interface in call sites that only need to populate token fields
// (e.g. token generators).
type TokenWriter interface {
	SetType(string)
	SetAccessToken(token string)
	SetRefreshToken(token string)
	SetClientID(clientID string)
	SetScopes(scopes types.Scopes)
	SetIssuedAt(issuedAt time.Time)
	SetAccessTokenExpiresIn(exp time.Duration)
	SetRefreshTokenExpiresIn(exp time.Duration)
	SetUserID(userID string)
	SetJwtID(id string)
}

// Token represents an issued OAuth 2.0 token. Implement this interface with
// your own data model (e.g. a database-backed struct) and pass instances to
// the grant flows and token generators.
//
// It composes TokenReader and TokenWriter so callers that only need read or
// write access can declare the narrower interface.
type Token interface {
	TokenReader
	TokenWriter
}

// ExtendableToken extends Token with an arbitrary key-value map for storing
// application-specific data alongside the standard token fields.
type ExtendableToken interface {
	Token

	// GetExtraData / SetExtraData get and set the additional data map.
	GetExtraData() map[string]interface{}
	SetExtraData(data map[string]interface{})
}
