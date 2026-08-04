package rfc6750

import (
	"context"
	"time"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/requests"
)

// ExpiresInGenerator is a pluggable function for computing access/refresh token
// lifetimes dynamically (e.g. shorter expiry for high-risk clients). If nil,
// the static duration from TokenGeneratorOptions is used.
type ExpiresInGenerator func(ctx context.Context, grantType string, client models.Client) time.Duration

// RandStringGenerator is a pluggable function for producing the opaque token
// string itself (e.g. to use a different charset or prefix). If nil, a
// cryptographically random string of the configured length is generated.
type RandStringGenerator func(ctx context.Context, grantType string, client models.Client) (string, error)

// TokenGenerator is the common interface implemented by both
// OpaqueAccessTokenGenerator and OpaqueRefreshTokenGenerator.
type TokenGenerator interface {
	Generate(token models.Token, r *requests.TokenRequest) error
}
