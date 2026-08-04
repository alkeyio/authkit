package rfc6750

import (
	"errors"
	"time"

	"github.com/alkeyio/authkit/utils"
)

var (
	ErrNilAccessTokenGenerator  = errors.New("access token generator is nil")
	ErrNilRefreshTokenGenerator = errors.New("refresh token generator is nil")
)

const (
	// DefaultExpiresIn is the shared base expiry duration used by
	// TokenGeneratorOptions when no ExpiresInGenerator is configured.
	DefaultExpiresIn = time.Minute * 60

	// DefaultTokenLength is the number of characters in a generated opaque
	// token string, shared by both access and refresh token generators.
	DefaultTokenLength = 48
)

// BearerTokenGeneratorOptions holds the access and refresh token generators
// used by BearerTokenGenerator. Use NewBearerTokenGeneratorOptions for
// secure defaults, then override with Set* methods as needed.
type BearerTokenGeneratorOptions struct {
	atGen TokenGenerator
	rfGen TokenGenerator
}

// NewBearerTokenGeneratorOptions returns options pre-configured with an
// OpaqueAccessTokenGenerator and an OpaqueRefreshTokenGenerator.
func NewBearerTokenGeneratorOptions() *BearerTokenGeneratorOptions {
	return &BearerTokenGeneratorOptions{
		atGen: NewOpaqueAccessTokenGenerator(),
		rfGen: NewOpaqueRefreshTokenGenerator(),
	}
}

// SetAccessTokenGenerator overrides the access token generator.
func (cfg *BearerTokenGeneratorOptions) SetAccessTokenGenerator(gen TokenGenerator) *BearerTokenGeneratorOptions {
	cfg.atGen = gen
	return cfg
}

// SetRefreshTokenGenerator overrides the refresh token generator.
func (cfg *BearerTokenGeneratorOptions) SetRefreshTokenGenerator(gen TokenGenerator) *BearerTokenGeneratorOptions {
	cfg.rfGen = gen
	return cfg
}

// Validate returns an error if either generator is nil.
func (cfg *BearerTokenGeneratorOptions) Validate() error {
	if utils.IsNil(cfg.atGen) {
		return ErrNilAccessTokenGenerator
	}

	if utils.IsNil(cfg.rfGen) {
		return ErrNilRefreshTokenGenerator
	}

	return nil
}

// TokenGeneratorOptions holds the configuration for OpaqueAccessTokenGenerator
// and OpaqueRefreshTokenGenerator. Use NewTokenGeneratorOptions for secure
// defaults, then chain Set* calls to customise behaviour.
type TokenGeneratorOptions struct {
	tokenLength         int
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
}

// NewTokenGeneratorOptions returns options with DefaultTokenLength and
// DefaultExpiresIn. All generator hooks are nil, meaning the built-in
// crypto/rand implementation and the static expiry are used.
func NewTokenGeneratorOptions() *TokenGeneratorOptions {
	return &TokenGeneratorOptions{
		tokenLength: DefaultTokenLength,
		expiresIn:   DefaultExpiresIn,
	}
}

// SetTokenLength overrides the length of the generated token string.
// Values less than 1 will cause ErrInvalidTokenLength at generation time.
func (opts *TokenGeneratorOptions) SetTokenLength(l int) *TokenGeneratorOptions {
	opts.tokenLength = l
	return opts
}

// SetExpiresIn overrides the static token lifetime used when no
// ExpiresInGenerator is configured.
func (opts *TokenGeneratorOptions) SetExpiresIn(exp time.Duration) *TokenGeneratorOptions {
	opts.expiresIn = exp
	return opts
}

// SetExpiresInGenerator registers a per-request expiry hook. When set it
// takes precedence over the static expiresIn value. Pass nil to revert to
// the static value.
func (opts *TokenGeneratorOptions) SetExpiresInGenerator(fn ExpiresInGenerator) *TokenGeneratorOptions {
	opts.expiresInGenerator = fn
	return opts
}

// SetRandStringGenerator registers a custom token-generation hook. When set
// it replaces the built-in crypto/rand implementation entirely. Pass nil to
// revert to the default.
func (opts *TokenGeneratorOptions) SetRandStringGenerator(fn RandStringGenerator) *TokenGeneratorOptions {
	opts.randStringGenerator = fn
	return opts
}
