package authorizationcode

import (
	"context"
	"net/http"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
)

// ClientManager handles client lookup and authentication at the token endpoint.
// Typically backed by clientauth.Manager from rfc6749/client_authentication.
type ClientManager interface {
	// QueryByClientID retrieves the client with the given client_id.
	// Return (nil, nil) when the client does not exist.
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)

	// Authenticate validates the client credentials carried in the request using
	// one of the permitted authMethods. Returns the authenticated client or an error.
	Authenticate(r *http.Request, authMethods map[types.ClientAuthMethod]bool, endpointName string) (models.Client, error)
}

// UserManager resolves the resource owner linked to an authorization code.
type UserManager interface {
	// QueryUserByCode returns the user associated with code. Return (nil, nil)
	// when no user can be found; the flow treats this as an invalid_grant error.
	QueryUserByCode(ctx context.Context, code models.AuthorizationCode, r *requests.TokenRequest) (models.User, error)
}

// AuthCodeManager controls the full lifecycle of an authorization code: creation,
// persistence, lookup, and deletion after a successful token exchange.
type AuthCodeManager interface {
	// New allocates a blank AuthorizationCode ready to be populated by Generate.
	New() models.AuthorizationCode

	// QueryByCode retrieves the authorization code record matching code.
	// Return (nil, nil) when the code does not exist.
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)

	// Generate populates authCode with a random code value, expiry, and any
	// request-derived data (client_id, redirect_uri, scopes, user_id).
	Generate(ctx context.Context, authCode models.AuthorizationCode, r *requests.AuthorizationRequest) error

	// Save persists authCode to the backing store.
	Save(ctx context.Context, code models.AuthorizationCode) error

	// DeleteByCode removes the authorization code after it has been exchanged
	// for a token, preventing reuse (RFC 6749 §4.1.2).
	DeleteByCode(ctx context.Context, code string) error
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

// AuthorizationRequestValidator is an extension hook called during
// ValidateAuthorizationRequest, after the built-in checks pass.
// Register with Config.RegisterExtension (e.g. PKCE, OIDC nonce validation).
type AuthorizationRequestValidator interface {
	ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
}

// ConsentRequestValidator is an extension hook called during
// ValidateConsentRequest, after the built-in checks pass.
type ConsentRequestValidator interface {
	ValidateConsentRequest(r *requests.AuthorizationRequest) error
}

// AuthCodeProcessor is an extension hook called after the authorization code is
// generated and before it is saved. Use it to attach extra data to the code
// (e.g. PKCE stores code_challenge) or add parameters to the redirect response.
type AuthCodeProcessor interface {
	ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]interface{}) error
}

// TokenRequestValidator is an extension hook called during ValidateTokenRequest,
// after the built-in checks pass (e.g. PKCE verifies code_verifier here).
type TokenRequestValidator interface {
	ValidateTokenRequest(r *requests.TokenRequest) error
}

// TokenProcessor is an extension hook called after the token is generated and
// before the response is written. Use it to add extra fields to the token
// response (e.g. OIDC attaches id_token here).
type TokenProcessor interface {
	ProcessToken(ctx context.Context, r *requests.TokenRequest, token models.TokenReader, data map[string]interface{}) error
}
