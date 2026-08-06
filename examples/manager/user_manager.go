package manager

import (
	"context"
	"net/http"
	"sync"
	"time"

	authkitmodels "github.com/alkeyio/authkit/models"
	authkitrequests "github.com/alkeyio/authkit/requests"
)

// User is an in-memory user model with standard OIDC profile claims
// (OpenID Connect Core 1.0 §5.1).
type User struct {
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	Password      string    `json:"-"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	GivenName     string    `json:"given_name"`
	FamilyName    string    `json:"family_name"`
	MiddleName    string    `json:"middle_name"`
	Nickname      string    `json:"nickname"`
	Picture       string    `json:"picture"`
	Website       string    `json:"website"`
	PhoneNumber   string    `json:"phone_number"`
	Locale        string    `json:"locale"`
	ZoneInfo      string    `json:"zoneinfo"`
	UpdatedAt     time.Time `json:"updated_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// GetUserID returns the unique identifier of the user.
func (u *User) GetUserID() string {
	return u.UserID
}

// UserManager is an in-memory user store for example purposes.
type UserManager struct {
	lock       sync.RWMutex
	byID       map[string]*User
	byUsername map[string]*User
}

// NewUserManager creates a new empty UserManager.
func NewUserManager() *UserManager {
	return &UserManager{
		byID:       make(map[string]*User),
		byUsername: make(map[string]*User),
	}
}

// Register adds a new user to the manager. If a user with the same UserID or
// Username already exists, it is overwritten.
func (m *UserManager) Register(u *User) {
	if u == nil || u.UserID == "" {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.byID[u.UserID] = u
	m.byUsername[u.Username] = u
}

// QueryUserByCode retrieves the user associated with the given authorization code.
// Returns (nil, nil) when no user is found for the code's user ID.
func (m *UserManager) QueryUserByCode(_ context.Context, code authkitmodels.AuthorizationCode, _ *authkitrequests.TokenRequest) (authkitmodels.User, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	u, ok := m.byID[code.GetUserID()]
	if !ok {
		return nil, nil
	}

	return u, nil
}

// Authenticate verifies the user's credentials and returns the authenticated user.
// Returns (nil, nil) when the credentials are invalid.
func (m *UserManager) Authenticate(_ context.Context, username, password string, _ authkitmodels.Client, _ *http.Request) (authkitmodels.User, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	u, ok := m.byUsername[username]
	if !ok || u.Password != password {
		return nil, nil
	}

	return u, nil
}
