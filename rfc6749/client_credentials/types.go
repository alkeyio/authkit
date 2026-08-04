package clientcredentials

import (
	"context"
	"net/http"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
)

// ClientManager authenticates the client application at the token endpoint.
// Typically backed by clientauth.Manager from rfc6749/client_authentication.
type ClientManager interface {
	// Authenticate validates the client credentials carried in the request using
	// one of the permitted authMethods. Returns the authenticated client or an error.
	Authenticate(r *http.Request, supportedMethods map[types.ClientAuthMethod]bool, endpoint string) (models.Client, error)
}

// TokenManager generates and persists access (and optionally refresh) tokens.
type TokenManager interface {
	// New allocates a blank Token ready to be populated by Generate.
	New() models.Token

	// Generate populates token with a value, expiry, scopes, and client binding.
	// includeRefreshToken is always false for this grant — RFC 6749 §4.4.3
	// states that a refresh token SHOULD NOT be issued in the client credentials flow.
	Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error

	// Save persists the token to the backing store.
	Save(ctx context.Context, token models.Token) error
}

// TokenRequestValidator is an extension hook called during ValidateTokenRequest,
// after the built-in checks pass.
type TokenRequestValidator interface {
	ValidateTokenRequest(r *requests.TokenRequest) error
}

// TokenProcessor is an extension hook called after the token is generated and
// before the response is written. Use it to add extra fields to the token
// response (e.g. attaching a custom claim).
type TokenProcessor interface {
	ProcessToken(r *requests.TokenRequest, token models.Token, data map[string]interface{}) error
}
