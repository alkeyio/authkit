package rfc9068

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	autherrors "github.com/tniah/authkit/errors"
)

// DefaultExpiresIn is the JWT access token lifetime used when no
// ExpiresInGenerator is configured.
const DefaultExpiresIn = time.Minute * 60

// GeneratorConfig holds all settings for JWTAccessTokenGenerator. Use
// NewGeneratorConfig to obtain a value with a secure default expiry, then
// chain Set* calls to configure the issuer, signing key, and optional hooks.
type GeneratorConfig struct {
	issuer              string
	issuerGenerator     IssuerGenerator
	audience            string
	audienceGenerator   AudienceGenerator
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	signingKey          []byte
	signingKeyMethod    jwt.SigningMethod
	signingKeyID        string
	signingKeyGenerator SigningKeyGenerator
	extraClaimGenerator ExtraClaimGenerator
	jwtIDGenerator      JWTIDGenerator
}

// NewGeneratorConfig returns a GeneratorConfig with DefaultExpiresIn.
// All generator hooks are nil, meaning static config values are used.
func NewGeneratorConfig() *GeneratorConfig {
	return &GeneratorConfig{expiresIn: DefaultExpiresIn}
}

// SetIssuer sets the static issuer claim (iss). Ignored when SetIssuerGenerator is set.
func (cfg *GeneratorConfig) SetIssuer(iss string) *GeneratorConfig {
	cfg.issuer = iss
	return cfg
}

// SetIssuerGenerator registers a per-request issuer hook. Takes precedence over
// SetIssuer when set.
func (cfg *GeneratorConfig) SetIssuerGenerator(fn IssuerGenerator) *GeneratorConfig {
	cfg.issuerGenerator = fn
	return cfg
}

// SetAudience sets the static audience claim (aud). The value should be the
// resource server identifier (e.g. "https://api.example.com"), per RFC 9068 §2.2.
// Ignored when SetAudienceGenerator is set.
func (cfg *GeneratorConfig) SetAudience(aud string) *GeneratorConfig {
	cfg.audience = aud
	return cfg
}

// SetAudienceGenerator registers a per-request audience hook. Takes precedence
// over SetAudience when set.
func (cfg *GeneratorConfig) SetAudienceGenerator(fn AudienceGenerator) *GeneratorConfig {
	cfg.audienceGenerator = fn
	return cfg
}

// SetExpiresIn overrides the static token lifetime. Ignored when
// SetExpiresInGenerator is set.
func (cfg *GeneratorConfig) SetExpiresIn(exp time.Duration) *GeneratorConfig {
	cfg.expiresIn = exp
	return cfg
}

// SetExpiresInGenerator registers a per-request expiry hook. Takes precedence
// over SetExpiresIn when set.
func (cfg *GeneratorConfig) SetExpiresInGenerator(fn ExpiresInGenerator) *GeneratorConfig {
	cfg.expiresInGenerator = fn
	return cfg
}

// SetSigningKey sets the static signing key, algorithm, and optional key ID (kid).
// Required unless SetSigningKeyGenerator is used.
func (cfg *GeneratorConfig) SetSigningKey(key []byte, method jwt.SigningMethod, keyID ...string) *GeneratorConfig {
	cfg.signingKey = key
	cfg.signingKeyMethod = method

	if len(keyID) > 0 {
		cfg.signingKeyID = keyID[0]
	}

	return cfg
}

// SetSigningKeyGenerator registers a per-request signing key hook. Takes
// precedence over SetSigningKey when set.
func (cfg *GeneratorConfig) SetSigningKeyGenerator(fn SigningKeyGenerator) *GeneratorConfig {
	cfg.signingKeyGenerator = fn
	return cfg
}

// SetExtraClaimGenerator registers a hook for adding extra claims to the JWT
// (e.g. roles, tenant ID). Claims returned by this hook are merged into the
// standard claim set. Protected claims (iss, sub, aud, exp, iat, jti,
// client_id, scope) are silently skipped and cannot be overridden.
func (cfg *GeneratorConfig) SetExtraClaimGenerator(fn ExtraClaimGenerator) *GeneratorConfig {
	cfg.extraClaimGenerator = fn
	return cfg
}

// SetJWTIDGenerator registers a custom jti generator. When set, it replaces
// the default UUID-based implementation.
func (cfg *GeneratorConfig) SetJWTIDGenerator(fn JWTIDGenerator) *GeneratorConfig {
	cfg.jwtIDGenerator = fn
	return cfg
}

// ValidateConfig returns an error if any required configuration is missing.
// Call this via MustJWTAccessTokenGenerator rather than directly.
func (cfg *GeneratorConfig) ValidateConfig() error {
	if cfg.issuer == "" && cfg.issuerGenerator == nil {
		return autherrors.ErrMissingIssuer
	}

	if cfg.audience == "" && cfg.audienceGenerator == nil {
		return autherrors.ErrMissingAudience
	}

	if cfg.expiresIn == 0 && cfg.expiresInGenerator == nil {
		return autherrors.ErrMissingExpiresIn
	}

	if cfg.signingKey == nil && cfg.signingKeyGenerator == nil {
		return autherrors.ErrMissingSigningKey
	}

	if cfg.signingKey != nil && cfg.signingKeyMethod == nil {
		return autherrors.ErrMissingSigningKeyMethod
	}

	// RFC 9068 §2.1: JWT access tokens MUST NOT use "none" as the signing algorithm.
	if cfg.signingKey != nil && cfg.signingKeyMethod == jwt.SigningMethodNone {
		return autherrors.ErrInsecureSigningMethod
	}

	return nil
}
