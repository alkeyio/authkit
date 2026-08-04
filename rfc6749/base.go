package rfc6749

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/utils"
)

// TokenFlowMixin provides shared helpers for grant flows that issue tokens.
// Embed it in a Flow struct to reuse common token response behaviour.
type TokenFlowMixin struct{}

// StandardTokenData builds the JSON-serializable token response body required
// by RFC 6749 §5.1. It always includes "token_type", "access_token", and
// "expires_in". "refresh_token" is omitted when the token carries no refresh
// token; "scope" is omitted when the token has no scopes.
func (f *TokenFlowMixin) StandardTokenData(token models.Token) map[string]interface{} {
	data := map[string]interface{}{
		"token_type":   token.GetType(),
		"access_token": token.GetAccessToken(),
		"expires_in":   token.GetAccessTokenExpiresIn().Seconds(),
	}

	if refreshToken := token.GetRefreshToken(); refreshToken != "" {
		data["refresh_token"] = refreshToken
	}

	if scopes := token.GetScopes(); len(scopes) > 0 {
		data["scope"] = strings.Join(scopes.String(), " ")
	}

	return data
}

// HandleTokenResponse writes a successful token response (HTTP 200) with the
// appropriate JSON content-type headers and the provided data payload.
func (f *TokenFlowMixin) HandleTokenResponse(rw http.ResponseWriter, data map[string]interface{}) error {
	for k, v := range utils.JSONHeaders() {
		rw.Header().Set(k, v)
	}

	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(data)
}
