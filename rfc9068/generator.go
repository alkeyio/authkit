package rfc9068

import (
	"context"
	"errors"
	"strings"
	"time"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// protectedClaims is the set of standard RFC 9068 claim names that
// ExtraClaimGenerator is not allowed to override.
var protectedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true,
	"exp": true, "iat": true, "jti": true,
	"client_id": true, "scope": true,
}

// ErrNilClient is returned by Generate when the token request carries no client.
var ErrNilClient = errors.New("client is nil")

// JWTAccessTokenGenerator issues RFC 9068 JWT Access Tokens. It is the JWT
// counterpart to rfc6750.OpaqueAccessTokenGenerator and satisfies the same
// rfc6750.TokenGenerator interface, so it can be used as a drop-in replacement
// in BearerTokenGeneratorOptions.SetAccessTokenGenerator.
type JWTAccessTokenGenerator struct {
	*GeneratorConfig
}

// NewJWTAccessTokenGenerator creates a JWTAccessTokenGenerator from cfg without
// validating it. Prefer MustJWTAccessTokenGenerator for production use.
func NewJWTAccessTokenGenerator(cfg *GeneratorConfig) *JWTAccessTokenGenerator {
	return &JWTAccessTokenGenerator{cfg}
}

// MustJWTAccessTokenGenerator creates a JWTAccessTokenGenerator after validating
// cfg. Returns an error if issuer, signing key, or expiry configuration is missing.
func MustJWTAccessTokenGenerator(cfg *GeneratorConfig) (*JWTAccessTokenGenerator, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return NewJWTAccessTokenGenerator(cfg), nil
}

// Generate populates token with a signed JWT access token derived from r.
// The JWT carries the standard RFC 9068 claims (iss, sub, aud, exp, iat, jti,
// client_id, scope). Extra claims can be added via GeneratorConfig.SetExtraClaimGenerator.
// User may be nil (e.g. client credentials); in that case sub is set to client_id.
func (g *JWTAccessTokenGenerator) Generate(ctx context.Context, token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	if utils.IsNil(client) {
		return ErrNilClient
	}

	clientID := client.GetClientID()
	token.SetClientID(clientID)

	sub := ""
	if !utils.IsNil(r.User) {
		sub = r.User.GetUserID()
	}
	token.SetUserID(sub)

	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now().UTC().Round(time.Second)
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(ctx, r.GrantType.String(), client)
	token.SetAccessTokenExpiresIn(expiresIn)

	jwtID := token.GetJwtID()
	if jwtID == "" {
		jwtID = g.jwtIDHandler(ctx, r.GrantType.String(), client)
		token.SetJwtID(jwtID)
	}

	claims := utils.JWTClaim{
		"iss":       g.issuerHandler(ctx, client),
		"exp":       jwt.NewNumericDate(issuedAt.Add(expiresIn)),
		"aud":       g.audienceHandler(ctx, client),
		"client_id": clientID,
		"iat":       jwt.NewNumericDate(issuedAt),
		"jti":       jwtID,
	}

	if sub != "" {
		claims["sub"] = sub
	} else {
		claims["sub"] = clientID
	}

	if len(allowedScopes) > 0 {
		claims["scope"] = strings.Join(allowedScopes.String(), " ")
	}

	if fn := g.extraClaimGenerator; fn != nil {
		extraClaims, err := fn(ctx, r.GrantType.String(), client, r.User, allowedScopes)
		if err != nil {
			return err
		}

		// Skip protected standard claims to prevent accidental or malicious override.
		for k, v := range extraClaims {
			if !protectedClaims[k] {
				claims[k] = v
			}
		}
	}

	signingKey, signingMethod, signingKeyID, err := g.signingKeyHandler(ctx, client)
	if err != nil {
		return err
	}

	// RFC 9068 §2.1: MUST NOT use "none" — guard against signingKeyGenerator returning it.
	if signingMethod == jwt.SigningMethodNone {
		return autherrors.ErrInsecureSigningMethod
	}

	t, err := utils.NewJWTToken(signingKey, signingMethod, signingKeyID)
	if err != nil {
		return err
	}

	jwtToken, err := t.Generate(claims, utils.JWTHeader{"typ": "at+JWT"})
	if err != nil {
		return err
	}

	token.SetAccessToken(jwtToken)
	return nil
}

// issuerHandler returns the issuer claim. Delegates to IssuerGenerator if set,
// otherwise returns the static issuer from config.
func (g *JWTAccessTokenGenerator) issuerHandler(ctx context.Context, client models.Client) string {
	if fn := g.issuerGenerator; fn != nil {
		return fn(ctx, client)
	}

	return g.issuer
}

// audienceHandler returns the audience claim. Delegates to AudienceGenerator
// if set, otherwise returns the static audience from config.
func (g *JWTAccessTokenGenerator) audienceHandler(ctx context.Context, client models.Client) string {
	if fn := g.audienceGenerator; fn != nil {
		return fn(ctx, client)
	}

	return g.audience
}

// expiresInHandler returns the token lifetime. Delegates to ExpiresInGenerator
// if set, otherwise returns the static expiresIn value from config.
func (g *JWTAccessTokenGenerator) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}

// signingKeyHandler returns the signing key, method, and key ID. Delegates to
// SigningKeyGenerator if set, otherwise returns the static values from config.
func (g *JWTAccessTokenGenerator) signingKeyHandler(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if fn := g.signingKeyGenerator; fn != nil {
		return fn(ctx, client)
	}

	return g.signingKey, g.signingKeyMethod, g.signingKeyID, nil
}

// jwtIDHandler returns the JWT ID. Delegates to JWTIDGenerator if set,
// otherwise generates a random UUID without hyphens.
func (g *JWTAccessTokenGenerator) jwtIDHandler(ctx context.Context, grantType string, client models.Client) string {
	if fn := g.jwtIDGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return strings.ReplaceAll(uuid.NewString(), "-", "")
}
