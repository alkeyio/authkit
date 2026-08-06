package codegen

import (
	"context"
	"errors"
	"time"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
	"github.com/alkeyio/authkit/utils"
)

// Sentinel errors returned by Generate and genCode.
var (
	ErrNilClient         = errors.New("client is nil")
	ErrNilUser           = errors.New("user is nil")
	ErrInvalidCodeLength = errors.New("code length must be greater than 0")
)

// Generator populates an AuthorizationCode from an AuthorizationRequest.
// It is the default implementation used by the Authorization Code flow
// (RFC 6749 §4.1.2). Behaviour can be customised through Options.
type Generator struct {
	*Options
}

// New returns a Generator using the first Options value supplied, or
// DefaultOptions if none is provided.
func New(opts ...*Options) *Generator {
	if len(opts) > 0 {
		return &Generator{opts[0]}
	}

	defaultOpts := NewOptions()
	return &Generator{defaultOpts}
}

// Generate populates authCode with all fields required by RFC 6749 §4.1.2:
// code, client_id, user_id, redirect_uri, response_type, scope, state,
// auth_time, and expires_in. If an ExtraDataGenerator is configured and
// authCode implements models.ExtendableAuthorizationCode, its output is stored
// via SetExtraData.
func (g *Generator) Generate(ctx context.Context, authCode models.AuthorizationCode, r *requests.AuthorizationRequest) error {
	client := r.Client
	if utils.IsNil(client) {
		return ErrNilClient
	}

	user := r.User
	if utils.IsNil(user) {
		return ErrNilUser
	}

	code, err := g.genCode(ctx, r.GrantType, client)
	if err != nil {
		return err
	}

	authCode.SetCode(code)
	authCode.SetClientID(client.GetClientID())
	authCode.SetUserID(user.GetUserID())
	authCode.SetRedirectURI(r.RedirectURI)
	authCode.SetResponseType(r.ResponseType)
	authCode.SetScopes(r.Scopes)
	authCode.SetState(r.State)
	authCode.SetAuthTime(time.Now().UTC().Round(time.Second))
	exp := g.expiresInHandler(ctx, r.GrantType, client)
	authCode.SetExpiresIn(exp)

	if fn := g.extraDataGenerator; fn != nil {
		if extAuthCode, ok := authCode.(models.ExtendableAuthorizationCode); ok {
			data, err := fn(ctx, r)
			if err != nil {
				return err
			}
			extAuthCode.SetExtraData(data)
		}
	}

	return nil
}

// genCode returns the authorization code string. If a RandStringGenerator is
// configured it is called; otherwise a cryptographically secure random string
// of codeLength alphanumeric characters is produced via crypto/rand. Returns
// ErrInvalidCodeLength when codeLength < 1.
func (g *Generator) genCode(ctx context.Context, grantType types.GrantType, client models.Client) (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	if g.codeLength < 1 {
		return "", ErrInvalidCodeLength
	}

	return utils.GenerateRandString(g.codeLength, utils.AlphaNum)
}

// expiresInHandler returns the code lifetime. If an ExpiresInGenerator is
// configured it is called; otherwise the static expiresIn value is returned.
func (g *Generator) expiresInHandler(ctx context.Context, grantType types.GrantType, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}
