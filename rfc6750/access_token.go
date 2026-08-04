package rfc6750

import (
	"context"
	"errors"
	"time"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/utils"
)

const DefaultAccessTokenExpiresIn = time.Minute * 60

var (
	ErrNilClient          = errors.New("client is nil")
	ErrInvalidTokenLength = errors.New("token length must be greater than 0")
)

// OpaqueAccessTokenGenerator generates a random opaque (non-JWT) access token.
// All fields are configurable via TokenGeneratorOptions; defaults produce a
// 48-character random string with a 60-minute expiry.
type OpaqueAccessTokenGenerator struct {
	*TokenGeneratorOptions
}

// NewOpaqueAccessTokenGenerator creates a generator with optional custom options.
// If no options are provided, defaults from NewTokenGeneratorOptions() are used.
func NewOpaqueAccessTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueAccessTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueAccessTokenGenerator{opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions().SetExpiresIn(DefaultAccessTokenExpiresIn)
	return &OpaqueAccessTokenGenerator{defaultOpts}
}

// Generate populates token with an opaque access token derived from the request.
// User may be nil (e.g. client credentials flow); in that case UserID is left empty.
func (g *OpaqueAccessTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	if utils.IsNil(client) {
		return ErrNilClient
	}

	// Prefer request context so custom generators can do context-aware work
	// (e.g. database lookups). Fall back to Background when called outside
	//  an HTTP request (e.g. unit tests).
	ctx := context.Background()
	if r.Request != nil {
		ctx = r.Request.Context()
	}

	token.SetClientID(client.GetClientID())

	// User is optional (absent in client credentials flows).
	if !utils.IsNil(r.User) {
		token.SetUserID(r.User.GetUserID())
	}

	// Intersect requested scopes with the scopes allowed for this client.
	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now().UTC().Round(time.Second)
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(ctx, r.GrantType.String(), client)
	token.SetAccessTokenExpiresIn(expiresIn)

	opaqueToken, err := g.genToken(ctx, r.GrantType.String(), client)
	if err != nil {
		return err
	}

	token.SetAccessToken(opaqueToken)
	return nil
}

// expiresInHandler delegates to the custom ExpiresInGenerator if set,
// otherwise returns the static expiry duration from options.
func (g *OpaqueAccessTokenGenerator) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}

// genToken delegates to the custom RandStringGenerator if set,
// otherwise generates a cryptographically random string of configured length.
func (g *OpaqueAccessTokenGenerator) genToken(ctx context.Context, grantType string, c models.Client) (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn(ctx, grantType, c)
	}

	if g.tokenLength < 1 {
		return "", ErrInvalidTokenLength
	}

	return utils.GenerateRandString(g.tokenLength, utils.SecretCharset)
}
