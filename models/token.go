package models

import (
	"time"

	"github.com/tniah/authkit/types"
)

// Token represents an issued OAuth 2.0 token. Implement this interface with
// your own data model (e.g. a database-backed struct) and pass instances to
// the grant flows and token generators.
type Token interface {
	// GetType / SetType get and set the token type (e.g. "Bearer").
	GetType() string
	SetType(string)

	// GetAccessToken / SetAccessToken get and set the access token string.
	GetAccessToken() string
	SetAccessToken(token string)

	// GetRefreshToken / SetRefreshToken get and set the refresh token string.
	GetRefreshToken() string
	SetRefreshToken(token string)

	// GetClientID / SetClientID get and set the client identifier the token
	// was issued to.
	GetClientID() string
	SetClientID(clientID string)

	// GetScopes / SetScopes get and set the granted scopes.
	GetScopes() types.Scopes
	SetScopes(scopes types.Scopes)

	// GetIssuedAt / SetIssuedAt get and set the time the token was issued.
	GetIssuedAt() time.Time
	SetIssuedAt(issuedAt time.Time)

	// GetAccessTokenExpiresIn / SetAccessTokenExpiresIn get and set the
	// access token lifetime.
	GetAccessTokenExpiresIn() time.Duration
	SetAccessTokenExpiresIn(exp time.Duration)

	// GetRefreshTokenExpiresIn / SetRefreshTokenExpiresIn get and set the
	// refresh token lifetime.
	GetRefreshTokenExpiresIn() time.Duration
	SetRefreshTokenExpiresIn(exp time.Duration)

	// GetUserID / SetUserID get and set the user identifier the token was
	// issued for. Empty for client credentials grants.
	GetUserID() string
	SetUserID(userID string)

	// GetJwtID / SetJwtID get and set the JWT ID (jti) used in RFC 9068 JWT
	// access tokens. May be empty for opaque tokens.
	GetJwtID() string
	SetJwtID(id string)
}

// ExtendableToken extends Token with an arbitrary key-value map for storing
// application-specific data alongside the standard token fields.
type ExtendableToken interface {
	Token

	// GetExtraData / SetExtraData get and set the additional data map.
	GetExtraData() map[string]interface{}
	SetExtraData(data map[string]interface{})
}
