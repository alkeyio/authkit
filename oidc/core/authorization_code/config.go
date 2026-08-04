// Package authorizationcode implements the OpenID Connect ID Token extension
// for the Authorization Code grant (RFC 6749 §4.1). Register a Flow via
// cfg.RegisterExtension to add ID Token generation to the authorization code flow.
package authorizationcode

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/utils"
)

// DefaultExpiresIn is the default ID Token lifetime (60 minutes).
const DefaultExpiresIn = time.Minute * 60

// Config holds all dependencies and options for the OIDC Authorization Code
// extension. Use NewConfig() to get a config with sensible defaults, then chain
// Set* calls before passing to Must() or New().
type Config struct {
	// requireNonce controls whether the nonce parameter is mandatory in
	// authorization requests. Defaults to true per OIDC Core §3.1.2.1.
	requireNonce        bool
	issuer              string
	issuerGenerator     IssuerGenerator
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	signingKey          []byte
	signingKeyMethod    jwt.SigningMethod
	signingKeyID        string
	signingKeyGenerator SigningKeyGenerator
	extraClaimGenerator ExtraClaimGenerator
	existNonce          ExistNonce
}

// NewConfig returns a Config with secure defaults:
//   - nonce is required (OIDC Core §3.1.2.1).
//   - ID Token lifetime is 60 minutes.
func NewConfig() *Config {
	return &Config{
		requireNonce: true,
		expiresIn:    DefaultExpiresIn,
	}
}

// SetRequireNonce controls whether the nonce parameter is mandatory.
// Default: true. Set to false only when nonce replay protection is handled elsewhere.
func (cfg *Config) SetRequireNonce(value bool) *Config {
	cfg.requireNonce = value
	return cfg
}

// SetIssuer sets the static issuer claim (iss) in the ID Token.
// Mutually exclusive with SetIssuerGenerator; generator takes precedence.
func (cfg *Config) SetIssuer(iss string) *Config {
	cfg.issuer = iss
	return cfg
}

// SetIssuerGenerator sets a dynamic issuer resolver. When set, it is called
// per-request instead of using the static issuer value.
func (cfg *Config) SetIssuerGenerator(fn IssuerGenerator) *Config {
	cfg.issuerGenerator = fn
	return cfg
}

// SetExpiresIn sets the static ID Token lifetime. Default: 60 minutes.
// Mutually exclusive with SetExpiresInGenerator; generator takes precedence.
func (cfg *Config) SetExpiresIn(exp time.Duration) *Config {
	cfg.expiresIn = exp
	return cfg
}

// SetExpiresInGenerator sets a dynamic lifetime resolver. When set, it is
// called per-request instead of using the static expiresIn value.
func (cfg *Config) SetExpiresInGenerator(fn ExpiresInGenerator) *Config {
	cfg.expiresInGenerator = fn
	return cfg
}

// SetSigningKey sets the static signing key, method, and optional key ID used
// to sign ID Tokens. Mutually exclusive with SetSigningKeyGenerator.
func (cfg *Config) SetSigningKey(key []byte, method jwt.SigningMethod, keyID ...string) *Config {
	cfg.signingKey = key
	cfg.signingKeyMethod = method

	if len(keyID) > 0 {
		cfg.signingKeyID = keyID[0]
	}

	return cfg
}

// SetSigningKeyGenerator sets a dynamic signing key resolver. When set, it is
// called per-request instead of using the static signing key.
func (cfg *Config) SetSigningKeyGenerator(fn SigningKeyGenerator) *Config {
	cfg.signingKeyGenerator = fn
	return cfg
}

// SetExtraClaimGenerator sets a function that returns additional claims to
// merge into the ID Token. Extra claims may not override standard claims
// (iss, sub, aud, exp, iat, auth_time, nonce).
func (cfg *Config) SetExtraClaimGenerator(fn ExtraClaimGenerator) *Config {
	cfg.extraClaimGenerator = fn
	return cfg
}

// SetExistNonce sets a function that checks whether a nonce has already been
// used. When set, it is called during authorization request validation to
// prevent nonce replay attacks (OIDC Core §3.1.2.1).
func (cfg *Config) SetExistNonce(fn ExistNonce) *Config {
	cfg.existNonce = fn
	return cfg
}

// ValidateConfig checks that all required dependencies are set and returns the
// first sentinel error encountered. Call this via Must() rather than directly.
func (cfg *Config) ValidateConfig() error {
	if cfg.issuer == "" && utils.IsNil(cfg.issuerGenerator) {
		return autherrors.ErrMissingIssuer
	}

	if cfg.expiresIn == 0 && utils.IsNil(cfg.expiresInGenerator) {
		return autherrors.ErrMissingExpiresIn
	}

	if cfg.signingKey == nil && utils.IsNil(cfg.signingKeyGenerator) {
		return autherrors.ErrMissingSigningKey
	}

	if cfg.signingKey != nil && utils.IsNil(cfg.signingKeyMethod) {
		return autherrors.ErrMissingSigningKeyMethod
	}

	return nil
}
