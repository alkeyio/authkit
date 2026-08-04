package rfc6750

import (
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
)

// TokenTypeBearer is the OAuth2 token type string for Bearer tokens (RFC 6750).
const TokenTypeBearer = "Bearer"

// BearerTokenGenerator issues RFC 6750 Bearer tokens. It delegates access
// token generation to an OpaqueAccessTokenGenerator (or any TokenGenerator)
// and optionally issues a refresh token via a separate TokenGenerator.
// Both generators are configurable via BearerTokenGeneratorOptions.
type BearerTokenGenerator struct {
	*BearerTokenGeneratorOptions
}

// NewBearerTokenGenerator creates a BearerTokenGenerator with optional custom
// options. If no options are provided, defaults from NewBearerTokenGeneratorOptions
// are used, which set up opaque access and refresh token generators.
func NewBearerTokenGenerator(opts ...*BearerTokenGeneratorOptions) *BearerTokenGenerator {
	if len(opts) > 0 && opts[0] != nil {
		return &BearerTokenGenerator{opts[0]}
	}

	defaultOpts := NewBearerTokenGeneratorOptions()
	return &BearerTokenGenerator{defaultOpts}
}

// MustBearerTokenGenerator creates a BearerTokenGenerator after validating opts.
// Returns an error if opts fails validation (e.g. nil access or refresh token generator).
// If opts is nil, defaults from NewBearerTokenGeneratorOptions are used.
func MustBearerTokenGenerator(opts *BearerTokenGeneratorOptions) (*BearerTokenGenerator, error) {
	if opts == nil {
		opts = NewBearerTokenGeneratorOptions()
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return NewBearerTokenGenerator(opts), nil
}

// Generate populates token with a Bearer access token and, when includeRefreshToken
// is true, a refresh token.
func (g *BearerTokenGenerator) Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error {
	if includeRefreshToken {
		if err := g.rfGen.Generate(token, r); err != nil {
			return err
		}
	}

	if err := g.atGen.Generate(token, r); err != nil {
		return err
	}

	token.SetType(TokenTypeBearer)
	return nil
}
