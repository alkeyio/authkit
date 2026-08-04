package manager

import (
	"context"
	"sync"
	"time"

	"github.com/tniah/authkit/integrations/sql"
	authkitmodels "github.com/tniah/authkit/models"
	authkitcodegen "github.com/tniah/authkit/rfc6749/code_generator"
)

// AuthorizationCodeManager is an in-memory OAuth2 authorization code store for example purposes.
type AuthorizationCodeManager struct {
	lock  sync.RWMutex
	codes map[string]*sql.AuthorizationCode
	*authkitcodegen.Generator
}

// NewAuthorizationCodeManager creates a new AuthorizationCodeManager.
func NewAuthorizationCodeManager() *AuthorizationCodeManager {
	m := &AuthorizationCodeManager{
		codes: make(map[string]*sql.AuthorizationCode),
	}

	opts := authkitcodegen.NewOptions().SetExpiresIn(5 * time.Minute)
	m.Generator = authkitcodegen.New(opts)
	return m
}

// New returns a new empty AuthorizationCode instance satisfying the authkit model interface.
func (m *AuthorizationCodeManager) New() authkitmodels.AuthorizationCode {
	return &sql.AuthorizationCode{}
}

// QueryByCode retrieves an authorization code by its code value.
// Returns (nil, nil) when the code does not exist or has expired.
func (m *AuthorizationCodeManager) QueryByCode(_ context.Context, code string) (authkitmodels.AuthorizationCode, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	c, ok := m.codes[code]
	if !ok {
		return nil, nil
	}

	return c, nil
}

// Save persists a new authorization code.
// If the provided model is not a *sql.AuthorizationCode, all fields are
// copied via setters into a new instance before storing.
func (m *AuthorizationCodeManager) Save(_ context.Context, c authkitmodels.AuthorizationCode) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	entry, ok := c.(*sql.AuthorizationCode)
	if !ok {
		entry = &sql.AuthorizationCode{}
		entry.SetCode(c.GetCode())
		entry.SetClientID(c.GetClientID())
		entry.SetUserID(c.GetUserID())
		entry.SetRedirectURI(c.GetRedirectURI())
		entry.SetResponseType(c.GetResponseType())
		entry.SetScopes(c.GetScopes())
		entry.SetNonce(c.GetNonce())
		entry.SetState(c.GetState())
		entry.SetAuthTime(c.GetAuthTime())
		entry.SetExpiresIn(c.GetExpiresIn())
		entry.SetCodeChallenge(c.GetCodeChallenge())
		entry.SetCodeChallengeMethod(c.GetCodeChallengeMethod())
	}

	now := time.Now().UTC().Round(time.Second)
	entry.CreatedAt = now
	entry.UpdatedAt = now

	m.codes[entry.Code] = entry
	return nil
}

// DeleteByCode removes an authorization code from the store.
// It is a no-op when the code does not exist.
func (m *AuthorizationCodeManager) DeleteByCode(_ context.Context, code string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	delete(m.codes, code)
	return nil
}
