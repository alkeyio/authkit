package rfc6750

import (
	"context"
	"time"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/utils"
)

// DefaultRefreshTokenExpiresIn is the refresh token lifetime used when no
// ExpiresInGenerator is configured. 24 hours is a common default that balances
// usability with security; tighten it for high-security deployments.
const DefaultRefreshTokenExpiresIn = time.Hour * 24

// OpaqueRefreshTokenGenerator generates a random opaque refresh token.
// Default expiry is 24 hours (DefaultRefreshTokenExpiresIn).
type OpaqueRefreshTokenGenerator struct {
	*TokenGeneratorOptions
}

// NewOpaqueRefreshTokenGenerator creates a generator with optional custom options.
// If no options are provided, defaults from NewTokenGeneratorOptions() are used
// with the expiry overridden to DefaultRefreshTokenExpiresIn.
func NewOpaqueRefreshTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueRefreshTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueRefreshTokenGenerator{TokenGeneratorOptions: opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions().SetExpiresIn(DefaultRefreshTokenExpiresIn)
	return &OpaqueRefreshTokenGenerator{defaultOpts}
}

// Generate populates token with a refresh token and its expiry duration.
func (g *OpaqueRefreshTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	if utils.IsNil(r.Client) {
		return ErrNilClient
	}

	// Prefer request context for custom generators; fall back to Background.
	ctx := context.Background()
	if r.Request != nil {
		ctx = r.Request.Context()
	}

	expiresIn := g.expiresInHandler(ctx, r.GrantType.String(), r.Client)
	token.SetRefreshTokenExpiresIn(expiresIn)

	refreshToken, err := g.genToken(ctx, r.GrantType.String(), r.Client)
	if err != nil {
		return err
	}

	token.SetRefreshToken(refreshToken)
	return nil
}

// expiresInHandler delegates to the custom ExpiresInGenerator if set,
// otherwise returns the static expiry duration from options.
func (g *OpaqueRefreshTokenGenerator) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}

// genToken delegates to the custom RandStringGenerator if set,
// otherwise generates a cryptographically random string of configured length.
func (g *OpaqueRefreshTokenGenerator) genToken(ctx context.Context, gt string, c models.Client) (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn(ctx, gt, c)
	}

	if g.tokenLength < 1 {
		return "", ErrInvalidTokenLength
	}

	return utils.GenerateRandString(g.tokenLength, utils.SecretCharset)
}
