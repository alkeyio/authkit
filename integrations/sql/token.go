package sql

import (
	"time"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
)

// Compile-time check that *Token implements models.ExtendableToken.
var _ models.ExtendableToken = (*Token)(nil)

type Token struct {
	TokenType             string                 `json:"token_type"`
	AccessToken           string                 `json:"access_token"`
	RefreshToken          string                 `json:"refresh_token"`
	ClientID              string                 `json:"client_id"`
	Scopes                []string               `json:"scopes"`
	IssuedAt              time.Time              `json:"issued_at"`
	AccessTokenExpiresIn  time.Duration          `json:"access_token_expires_in"`
	RefreshTokenExpiresIn time.Duration          `json:"refresh_token_expires_in"`
	UserID                string                 `json:"user_id"`
	JwtID                 string                 `json:"jti"`
	Data                  map[string]interface{} `json:"data"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

func (t *Token) GetType() string {
	return t.TokenType
}

func (t *Token) SetType(typ string) {
	t.TokenType = typ
}

func (t *Token) GetAccessToken() string {
	return t.AccessToken
}

func (t *Token) SetAccessToken(tok string) {
	t.AccessToken = tok
}

func (t *Token) GetRefreshToken() string {
	return t.RefreshToken
}

func (t *Token) SetRefreshToken(tok string) {
	t.RefreshToken = tok
}

func (t *Token) GetClientID() string {
	return t.ClientID
}

func (t *Token) SetClientID(cID string) {
	t.ClientID = cID
}

func (t *Token) GetScopes() types.Scopes {
	return types.NewScopes(t.Scopes)
}

func (t *Token) SetScopes(s types.Scopes) {
	t.Scopes = s.String()
}

func (t *Token) GetIssuedAt() time.Time {
	return t.IssuedAt
}

func (t *Token) SetIssuedAt(iat time.Time) {
	t.IssuedAt = iat
}

func (t *Token) GetAccessTokenExpiresIn() time.Duration {
	return t.AccessTokenExpiresIn
}

func (t *Token) SetAccessTokenExpiresIn(exp time.Duration) {
	t.AccessTokenExpiresIn = exp
}

func (t *Token) GetRefreshTokenExpiresIn() time.Duration {
	return t.RefreshTokenExpiresIn
}

func (t *Token) SetRefreshTokenExpiresIn(exp time.Duration) {
	t.RefreshTokenExpiresIn = exp
}

func (t *Token) GetUserID() string {
	return t.UserID
}

func (t *Token) SetUserID(id string) {
	t.UserID = id
}

func (t *Token) GetJwtID() string {
	return t.JwtID
}

func (t *Token) SetJwtID(id string) {
	t.JwtID = id
}

func (t *Token) GetExtraData() map[string]interface{} {
	return t.Data
}

func (t *Token) SetExtraData(data map[string]interface{}) {
	t.Data = data
}
