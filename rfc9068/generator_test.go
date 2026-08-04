package rfc9068

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/integrations/sql"
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
)

func TestJWTAccessTokenGenerator(t *testing.T) {
	cfg := NewGeneratorConfig().
		SetIssuer("https://example.com").
		SetAudience("https://api.example.com").
		SetSigningKey([]byte("my-secret-key"), jwt.SigningMethodHS256, "my-kid-id").
		SetExpiresIn(time.Hour * 24)

	mockClient := &sql.Client{
		ClientID: uuid.NewString(),
		Scopes:   []string{"openid", "email", "profile"},
	}
	mockUser := &sql.User{
		UserID: uuid.NewString(),
	}

	t.Run("success with user", func(t *testing.T) {
		mockToken := &sql.Token{}
		generator := NewJWTAccessTokenGenerator(cfg)
		r := &requests.TokenRequest{
			GrantType: "password",
			Client:    mockClient,
			User:      mockUser,
			Scopes:    types.NewScopes([]string{"openid", "email", "phoneNumber"}),
			Request:   httptest.NewRequest("POST", "/token", nil),
		}
		err := generator.Generate(mockToken, r)
		assert.NoError(t, err)
		assert.Equal(t, mockClient.ClientID, mockToken.GetClientID())
		assert.Equal(t, mockUser.GetUserID(), mockToken.GetUserID())
		assert.Contains(t, mockToken.GetScopes().String(), "openid")
		assert.Contains(t, mockToken.GetScopes().String(), "email")
		assert.NotContains(t, mockToken.GetScopes().String(), "phoneNumber")
		assert.Equal(t, false, mockToken.GetIssuedAt().IsZero())
		assert.Equal(t, cfg.expiresIn, mockToken.GetAccessTokenExpiresIn())
		assert.NotEmpty(t, mockToken.GetJwtID())
		assert.NotEmpty(t, mockToken.GetAccessToken())
	})

	t.Run("nil client returns ErrNilClient", func(t *testing.T) {
		mockToken := &sql.Token{}
		generator := NewJWTAccessTokenGenerator(cfg)
		r := &requests.TokenRequest{
			GrantType: "password",
			Client:    nil,
			Request:   httptest.NewRequest("POST", "/token", nil),
		}
		err := generator.Generate(mockToken, r)
		assert.ErrorIs(t, err, ErrNilClient)
	})

	t.Run("nil user sets sub to client_id in JWT", func(t *testing.T) {
		mockToken := &sql.Token{}
		generator := NewJWTAccessTokenGenerator(cfg)
		r := &requests.TokenRequest{
			GrantType: "client_credentials",
			Client:    mockClient,
			User:      nil,
			Request:   httptest.NewRequest("POST", "/token", nil),
		}
		err := generator.Generate(mockToken, r)
		assert.NoError(t, err)
		// Token model stores empty user ID for client_credentials; JWT sub = client_id.
		assert.Empty(t, mockToken.GetUserID())
		assert.Equal(t, mockClient.ClientID, mockToken.GetClientID())
		assert.NotEmpty(t, mockToken.GetAccessToken())
	})

	t.Run("extra claims cannot override protected claims", func(t *testing.T) {
		cfgExtra := NewGeneratorConfig().
			SetIssuer("https://example.com").
			SetAudience("https://api.example.com").
			SetSigningKey([]byte("my-secret-key"), jwt.SigningMethodHS256).
			SetExpiresIn(time.Hour).
			SetExtraClaimGenerator(func(_ context.Context, _ string, _ models.Client, _ models.User, _ types.Scopes) (map[string]interface{}, error) {
				return map[string]interface{}{
					"iss":    "https://attacker.com", // protected — must be ignored
					"sub":    "hacked",               // protected — must be ignored
					"custom": "allowed",              // non-protected — must be included
				}, nil
			})
		mockToken := &sql.Token{}
		generator := NewJWTAccessTokenGenerator(cfgExtra)
		r := &requests.TokenRequest{
			GrantType: "password",
			Client:    mockClient,
			User:      mockUser,
			Request:   httptest.NewRequest("POST", "/token", nil),
		}
		err := generator.Generate(mockToken, r)
		assert.NoError(t, err)
		assert.NotEmpty(t, mockToken.GetAccessToken())
	})

	t.Run("signing method none returns ErrInsecureSigningMethod", func(t *testing.T) {
		cfgNone := NewGeneratorConfig().
			SetIssuer("https://example.com").
			SetAudience("https://api.example.com").
			SetExpiresIn(time.Hour).
			SetSigningKeyGenerator(func(_ context.Context, _ models.Client) ([]byte, jwt.SigningMethod, string, error) {
				return nil, jwt.SigningMethodNone, "", nil
			})
		mockToken := &sql.Token{}
		generator := NewJWTAccessTokenGenerator(cfgNone)
		r := &requests.TokenRequest{
			GrantType: "client_credentials",
			Client:    mockClient,
			Request:   httptest.NewRequest("POST", "/token", nil),
		}
		err := generator.Generate(mockToken, r)
		assert.ErrorIs(t, err, autherrors.ErrInsecureSigningMethod)
	})
}
