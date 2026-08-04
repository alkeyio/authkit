package authorizationcode

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/requests"
)

// IssuerGenerator is a function that returns the issuer (iss) claim value for
// an ID Token. Use this for per-client or dynamic issuer resolution.
type IssuerGenerator func(ctx context.Context, client models.Client) string

// ExpiresInGenerator is a function that returns the ID Token lifetime for a
// given grant type and client. Use this for per-client expiry policies.
type ExpiresInGenerator func(ctx context.Context, grantType string, client models.Client) time.Duration

// SigningKeyGenerator is a function that returns the signing key, method, and
// key ID used to sign an ID Token. Use this for per-client or rotating keys.
type SigningKeyGenerator func(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error)

// ExtraClaimGenerator is a function that returns additional claims to merge
// into the ID Token. It receives the grant type, client, and authenticated user.
type ExtraClaimGenerator func(ctx context.Context, grantType string, client models.Client, user models.User) (map[string]interface{}, error)

// ExistNonce is a function that reports whether the given nonce has already
// been used in a previous authorization request. Return true to reject the
// request and prevent nonce replay (OIDC Core §3.1.2.1).
type ExistNonce func(ctx context.Context, nonce string, r *requests.AuthorizationRequest) bool
