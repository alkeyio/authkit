package rfc7662

import (
	"context"
	"net/http"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/types"
)

// ClientManager authenticates the client calling the introspection endpoint
// and enforces per-token access control.
type ClientManager interface {
	// Authenticate verifies the client credentials and returns the authenticated
	// client. endpointName identifies the endpoint being accessed (used for
	// method-specific logic in multi-endpoint setups).
	Authenticate(ctx context.Context, r *http.Request, authMethods map[types.ClientAuthMethod]bool, endpointName string) (models.Client, error)

	// CheckPermission reports whether client is allowed to introspect token.
	// Return false to respond with access_denied.
	CheckPermission(client models.Client, token models.Token, r *http.Request) bool
}

// TokenManager looks up tokens by value and builds the introspection payload.
type TokenManager interface {
	// QueryByToken looks up the token by its string value. hint is the
	// token_type_hint from the request (maybe empty). Returns nil without
	// an error when the token does not exist.
	QueryByToken(ctx context.Context, token string, hint types.TokenTypeHint) (models.Token, error)

	// Inspect builds the RFC 7662 §2.2 claim set for an active token.
	// The returned map is merged with {"active": true} before writing the
	// response. Return nil to emit only {"active": true} with no extra claims.
	Inspect(client models.Client, token models.Token) map[string]interface{}
}
