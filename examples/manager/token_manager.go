package manager

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/alkeyio/authkit/integrations/sql"
	authkitmodels "github.com/alkeyio/authkit/models"
	authkitrequests "github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/rfc6750"
	authkittypes "github.com/alkeyio/authkit/types"
)

// TokenManager is an in-memory OAuth2 token store for example purposes.
type TokenManager struct {
	lock           sync.RWMutex
	byAccessToken  map[string]*sql.Token
	byRefreshToken map[string]*sql.Token
	gen            *rfc6750.BearerTokenGenerator
}

// NewTokenManager creates a new TokenManager with a default BearerTokenGenerator.
func NewTokenManager() *TokenManager {
	return &TokenManager{
		byAccessToken:  make(map[string]*sql.Token),
		byRefreshToken: make(map[string]*sql.Token),
		gen:            rfc6750.NewBearerTokenGenerator(),
	}
}

// NewTokenManagerWithGenerator creates a TokenManager using the provided BearerTokenGenerator.
// Use this to supply a custom access token generator such as a JWTAccessTokenGenerator.
func NewTokenManagerWithGenerator(gen *rfc6750.BearerTokenGenerator) *TokenManager {
	return &TokenManager{
		byAccessToken:  make(map[string]*sql.Token),
		byRefreshToken: make(map[string]*sql.Token),
		gen:            gen,
	}
}

// New returns a new empty Token instance satisfying the authkit model interface.
func (m *TokenManager) New() authkitmodels.Token {
	return &sql.Token{}
}

// Generate populates the token fields using the bearer token generator.
func (m *TokenManager) Generate(ctx context.Context, token authkitmodels.Token, r *authkitrequests.TokenRequest, includeRefreshToken bool) error {
	return m.gen.Generate(ctx, token, r, includeRefreshToken)
}

// Save persists a new token.
// If the provided model is not a *sql.Token, all fields are copied via setters
// into a new instance before storing.
func (m *TokenManager) Save(_ context.Context, token authkitmodels.Token) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	entry, ok := token.(*sql.Token)
	if !ok {
		entry = &sql.Token{}
		entry.SetType(token.GetType())
		entry.SetAccessToken(token.GetAccessToken())
		entry.SetRefreshToken(token.GetRefreshToken())
		entry.SetClientID(token.GetClientID())
		entry.SetScopes(token.GetScopes())
		entry.SetIssuedAt(token.GetIssuedAt())
		entry.SetAccessTokenExpiresIn(token.GetAccessTokenExpiresIn())
		entry.SetRefreshTokenExpiresIn(token.GetRefreshTokenExpiresIn())
		entry.SetUserID(token.GetUserID())
		entry.SetJwtID(token.GetJwtID())
		if ext, ok := token.(authkitmodels.ExtendableToken); ok {
			entry.SetExtraData(ext.GetExtraData())
		}
	}

	now := time.Now().UTC().Round(time.Second)
	entry.CreatedAt = now
	entry.UpdatedAt = now

	m.byAccessToken[entry.AccessToken] = entry
	if entry.RefreshToken != "" {
		m.byRefreshToken[entry.RefreshToken] = entry
	}

	return nil
}

// QueryByToken retrieves a token by its value and optional type hint.
// When hint is refresh_token, the refresh token index is searched first.
// Returns (nil, nil) when the token does not exist.
func (m *TokenManager) QueryByToken(_ context.Context, token string, hint authkittypes.TokenTypeHint) (authkitmodels.Token, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if hint.IsRefreshToken() {
		if t, ok := m.byRefreshToken[token]; ok {
			return t, nil
		}
	}

	if t, ok := m.byAccessToken[token]; ok {
		return t, nil
	}

	if !hint.IsRefreshToken() {
		if t, ok := m.byRefreshToken[token]; ok {
			return t, nil
		}
	}

	return nil, nil
}

// Inspect returns the RFC 7662 §2.2 introspection claims for an active token.
// The caller (introspection endpoint) merges these with {"active": true}; do not include it here.
func (m *TokenManager) Inspect(_ context.Context, _ authkitmodels.Client, token authkitmodels.Token) map[string]interface{} {
	data := make(map[string]interface{})

	if scopes := token.GetScopes(); len(scopes) > 0 {
		data["scope"] = strings.Join(scopes.String(), " ")
	}

	if clientID := token.GetClientID(); clientID != "" {
		data["client_id"] = clientID
		data["aud"] = clientID
	}

	if tokenType := token.GetType(); tokenType != "" {
		data["token_type"] = tokenType
	}

	if issuedAt := token.GetIssuedAt(); !issuedAt.IsZero() {
		data["iat"] = issuedAt.Unix()
		data["exp"] = issuedAt.Add(token.GetAccessTokenExpiresIn()).Unix()
	}

	if userID := token.GetUserID(); userID != "" {
		data["sub"] = userID
	}

	if jti := token.GetJwtID(); jti != "" {
		data["jti"] = jti
	}

	return data
}
