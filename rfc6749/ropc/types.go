package ropc

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

// UserManager verifies the resource owner's credentials supplied in the request.
type UserManager interface {
	// Authenticate checks username and password against the backing store.
	// Return (nil, nil) when the credentials are invalid; the flow treats this
	// as an invalid_grant error with a generic message to avoid leaking whether
	// the username exists.
	Authenticate(username string, password string, client models.Client, r *http.Request) (models.User, error)
}

// TokenManager generates and persists access (and optionally refresh) tokens.
type TokenManager interface {
	// New allocates a blank Token ready to be populated by Generate.
	New() models.Token

	// Generate populates token with a value, expiry, scopes, and client/user
	// binding. Set includeRefreshToken to true to also generate a refresh token.
	Generate(ctx context.Context, token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error

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
