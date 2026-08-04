package sql

import (
	"time"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
)

// Compile-time check that *AuthorizationCode implements models.ExtendableAuthorizationCode.
var _ models.ExtendableAuthorizationCode = (*AuthorizationCode)(nil)

type AuthorizationCode struct {
	Code                string                 `json:"code"`
	ClientID            string                 `json:"client_id"`
	UserID              string                 `json:"user_id"`
	RedirectURI         string                 `json:"redirect_uri"`
	ResponseType        string                 `json:"response_type"`
	Scopes              []string               `json:"scopes"`
	Nonce               string                 `json:"nonce"`
	State               string                 `json:"state"`
	AuthTime            time.Time              `json:"auth_time"`
	ExpiresIn           time.Duration          `json:"expires_in"`
	CodeChallenge       string                 `json:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
	Data                map[string]interface{} `json:"data"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

func (c *AuthorizationCode) GetCode() string {
	return c.Code
}

func (c *AuthorizationCode) SetCode(code string) {
	c.Code = code
}

func (c *AuthorizationCode) GetClientID() string {
	return c.ClientID
}

func (c *AuthorizationCode) SetClientID(clientID string) {
	c.ClientID = clientID
}

func (c *AuthorizationCode) GetUserID() string {
	return c.UserID
}

func (c *AuthorizationCode) SetUserID(userID string) {
	c.UserID = userID
}

func (c *AuthorizationCode) GetRedirectURI() string {
	return c.RedirectURI
}

func (c *AuthorizationCode) SetRedirectURI(redirectURI string) {
	c.RedirectURI = redirectURI
}

func (c *AuthorizationCode) GetResponseType() types.ResponseType {
	return types.NewResponseType(c.ResponseType)
}

func (c *AuthorizationCode) SetResponseType(rt types.ResponseType) {
	c.ResponseType = rt.String()
}

func (c *AuthorizationCode) GetScopes() types.Scopes {
	return types.NewScopes(c.Scopes)
}

func (c *AuthorizationCode) SetScopes(s types.Scopes) {
	c.Scopes = s.String()
}

func (c *AuthorizationCode) GetNonce() string {
	return c.Nonce
}

func (c *AuthorizationCode) SetNonce(nonce string) {
	c.Nonce = nonce
}

func (c *AuthorizationCode) GetState() string {
	return c.State
}

func (c *AuthorizationCode) SetState(state string) {
	c.State = state
}

func (c *AuthorizationCode) GetAuthTime() time.Time {
	return c.AuthTime
}

func (c *AuthorizationCode) SetAuthTime(authTime time.Time) {
	c.AuthTime = authTime
}

func (c *AuthorizationCode) GetExpiresIn() time.Duration {
	return c.ExpiresIn
}

func (c *AuthorizationCode) SetExpiresIn(expiresIn time.Duration) {
	c.ExpiresIn = expiresIn
}

func (c *AuthorizationCode) GetCodeChallenge() string {
	return c.CodeChallenge
}

func (c *AuthorizationCode) SetCodeChallenge(codeChallenge string) {
	c.CodeChallenge = codeChallenge
}

func (c *AuthorizationCode) GetCodeChallengeMethod() types.CodeChallengeMethod {
	return types.NewCodeChallengeMethod(c.CodeChallengeMethod)
}

func (c *AuthorizationCode) SetCodeChallengeMethod(m types.CodeChallengeMethod) {
	c.CodeChallengeMethod = m.String()
}

func (c *AuthorizationCode) GetExtraData() map[string]interface{} {
	return c.Data
}

func (c *AuthorizationCode) SetExtraData(data map[string]interface{}) {
	c.Data = data
}
