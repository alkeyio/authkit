package rfc9068

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/types"
)

// IssuerGenerator returns the issuer (iss) claim value for the given client.
// Use this for multi-tenant setups where the issuer varies per client.
type IssuerGenerator func(ctx context.Context, client models.Client) string

// AudienceGenerator returns the audience (aud) claim value for the given client.
// The audience identifies the resource server(s) that will accept the token
// (RFC 9068 §2.2). Use this when the target resource server varies per client
// or per request.
type AudienceGenerator func(ctx context.Context, client models.Client) string

// ExpiresInGenerator returns the token lifetime for the given grant type and
// client. Use this to apply per-client or per-grant expiry policies.
type ExpiresInGenerator func(ctx context.Context, grantType string, client models.Client) time.Duration

// SigningKeyGenerator returns the signing key, signing method, and key ID (kid)
// for the given client. Use this for key rotation or per-client signing keys.
type SigningKeyGenerator func(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error)

// ExtraClaimGenerator returns additional claims to merge into the JWT payload.
// It receives the full request context: grant type, client, user (may be nil),
// and the allowed scopes after intersection.
type ExtraClaimGenerator func(ctx context.Context, grantType string, client models.Client, user models.User, scopes types.Scopes) (map[string]interface{}, error)

// JWTIDGenerator returns a unique identifier for the jti claim. When nil,
// a random UUID without hyphens is used.
type JWTIDGenerator func(ctx context.Context, grantType string, client models.Client) string
