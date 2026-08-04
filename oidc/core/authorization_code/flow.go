package authorizationcode

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
	"github.com/alkeyio/authkit/utils"
)

var (
	// ErrNilAuthorizationCode is returned when the authorization code is nil.
	ErrNilAuthorizationCode = errors.New("authorization code is nil")
	// ErrMissingUserID is returned when the user ID is empty.
	ErrMissingUserID = errors.New("user ID is empty")
)

// Flow implements the OIDC ID Token extension for the Authorization Code grant.
// Register it via cfg.RegisterExtension on an authorization code Config.
type Flow struct {
	*Config
}

// New returns a Flow using the provided Config without validation.
func New(cfg *Config) *Flow {
	return &Flow{cfg}
}

// Must returns a Flow after validating cfg. Returns an error if any required
// dependency is missing.
func Must(cfg *Config) (*Flow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

// ValidateAuthorizationRequest validates OIDC-specific parameters in the
// /authorize request. It is a no-op when the openid scope is absent.
func (f *Flow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if isOIDCReq := r.Scopes.ContainOpenID(); !isOIDCReq {
		return nil
	}

	if err := f.validateNonce(r); err != nil {
		return err
	}

	return nil
}

// ValidateConsentRequest validates OIDC prompt rules at the consent step.
// It is a no-op when the openid scope is absent. When prompt is absent and
// user is nil, defaults to prompt=login so the handler can redirect to the
// login page.
func (f *Flow) ValidateConsentRequest(r *requests.AuthorizationRequest) error {
	if isOIDCReq := r.Scopes.ContainOpenID(); !isOIDCReq {
		return nil
	}

	if err := f.validatePrompt(r); err != nil {
		return err
	}

	user := r.User
	if len(r.Prompts) == 0 && utils.IsNil(user) {
		r.Prompts = types.Prompts{types.PromptLogin}
	}

	if utils.IsNil(user) && r.Prompts.ContainLogin() {
		return nil
	}

	if utils.IsNil(user) && r.Prompts.ContainNone() {
		return autherrors.LoginRequiredError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	if utils.IsNil(user) && r.Prompts.ContainConsent() {
		return autherrors.ConsentRequiredError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	if utils.IsNil(user) && r.Prompts.ContainSelectAccount() {
		return autherrors.AccountSelectionRequiredError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

// ProcessAuthorizationCode stores the nonce from the authorization request
// into the authorization code before it is persisted.
func (f *Flow) ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]interface{}) error {
	if utils.IsNil(authCode) {
		return ErrNilAuthorizationCode
	}

	authCode.SetNonce(r.Nonce)
	return nil
}

// ProcessToken generates an ID Token and adds it to the token response data
// under the "id_token" key. It is a no-op when the openid scope is absent.
func (f *Flow) ProcessToken(r *requests.TokenRequest, _ models.Token, data map[string]interface{}) error {
	if isOIDCReq := r.Scopes.ContainOpenID(); !isOIDCReq {
		return nil
	}

	if utils.IsNil(r.AuthCode) {
		return ErrNilAuthorizationCode
	}

	idToken, err := f.genIDToken(r)
	if err != nil {
		return err
	}

	data["id_token"] = idToken
	return nil
}

// validateNonce checks that nonce is present (when required) and has not been
// used before (when ExistNonce is configured).
func (f *Flow) validateNonce(r *requests.AuthorizationRequest) error {
	if err := r.CheckNonce(f.requireNonce); err != nil {
		return err
	}

	if fn := f.existNonce; fn != nil {
		if fn(r.Request.Context(), r.Nonce, r) {
			return autherrors.InvalidRequestError().
				WithDescription("\"nonce\" has been used").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}
	}

	return nil
}

// validatePrompt enforces prompt parameter rules. When prompt=login is present,
// max_age is reset to 0 to force re-authentication.
func (f *Flow) validatePrompt(r *requests.AuthorizationRequest) error {
	for _, prompt := range r.Prompts {
		// OIDC Core §3.1.2.1: prompt=none MUST NOT be combined with other values.
		if prompt.IsNone() && len(r.Prompts) > 1 {
			return autherrors.InvalidRequestError().
				WithDescription("The prompt parameter \"none\" must only be used as a single value").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}

		if prompt.IsLogin() {
			r.MaxAge = types.NewMaxAge(0)
		}
	}

	return nil
}

// genIDToken builds and signs an ID Token for the given token request.
// Extra claims from ExtraClaimGenerator are merged first; standard claims
// (iss, sub, aud, exp, iat, auth_time, nonce) are set afterward and always
// take precedence over any extra claim with the same key.
func (f *Flow) genIDToken(r *requests.TokenRequest) (string, error) {
	client := r.Client
	user := r.User
	authCode := r.AuthCode

	sub := ""
	if !utils.IsNil(user) {
		sub = user.GetUserID()
	}
	if sub == "" {
		return "", ErrMissingUserID
	}

	now := time.Now().UTC().Round(time.Second)
	claims := utils.JWTClaim{}

	// Merge extra claims first so standard claims set below take precedence.
	if fn := f.extraClaimGenerator; fn != nil {
		extraClaims, err := fn(r.Request.Context(), r.GrantType.String(), client, user)
		if err != nil {
			return "", err
		}
		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	authTime := authCode.GetAuthTime()
	if authTime.IsZero() {
		authTime = now
	}

	// Standard claims always override any extra claim with the same key.
	claims["iss"] = f.issuerHandler(r.Request.Context(), client)
	claims["sub"] = sub
	claims["aud"] = []string{client.GetClientID()}
	claims["exp"] = jwt.NewNumericDate(now.Add(f.expiresInHandler(r.Request.Context(), r.GrantType.String(), client)))
	claims["iat"] = jwt.NewNumericDate(now)
	claims["auth_time"] = jwt.NewNumericDate(authTime)

	// nonce comes from the authorization code; override any extra claim value.
	delete(claims, "nonce")
	if nonce := authCode.GetNonce(); nonce != "" {
		claims["nonce"] = nonce
	}

	key, method, keyID, err := f.signingKeyHandler(r.Request.Context(), client)
	if err != nil {
		return "", err
	}

	t, err := utils.NewJWTToken(key, method, keyID)
	if err != nil {
		return "", err
	}

	idToken, err := t.Generate(claims, utils.JWTHeader{})
	if err != nil {
		return "", err
	}

	return idToken, nil
}

// issuerHandler returns the issuer, preferring IssuerGenerator over the static value.
func (f *Flow) issuerHandler(ctx context.Context, client models.Client) string {
	if fn := f.issuerGenerator; fn != nil {
		return fn(ctx, client)
	}

	return f.issuer
}

// expiresInHandler returns the ID Token lifetime, preferring ExpiresInGenerator over the static value.
func (f *Flow) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := f.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return f.expiresIn
}

// signingKeyHandler returns the signing key, method, and key ID, preferring
// SigningKeyGenerator over the static values.
func (f *Flow) signingKeyHandler(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if fn := f.signingKeyGenerator; fn != nil {
		return fn(ctx, client)
	}

	return f.signingKey, f.signingKeyMethod, f.signingKeyID, nil
}
