package authorizationcode

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/mocks/oidc/core/authorization_code"
)

func TestConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig()
		assert.Equal(t, DefaultExpiresIn, cfg.expiresIn)

		cfg.SetRequireNonce(false)
		assert.False(t, cfg.requireNonce)

		cfg.SetIssuer("https://example.com")
		assert.Equal(t, "https://example.com", cfg.issuer)

		issGen := oidc.NewMockIssuerGenerator(t).Execute
		cfg.SetIssuerGenerator(issGen)
		assert.NotNil(t, cfg.issuerGenerator)

		cfg.SetExpiresIn(time.Second * 60)
		assert.Equal(t, time.Second*60, cfg.expiresIn)

		expGen := oidc.NewMockExpiresInGenerator(t).Execute
		cfg.SetExpiresInGenerator(expGen)
		assert.NotNil(t, cfg.expiresInGenerator)

		cfg.SetSigningKey([]byte("test"), jwt.SigningMethodHS256, "my-kid")
		assert.Equal(t, []byte("test"), cfg.signingKey)
		assert.Equal(t, jwt.SigningMethodHS256, cfg.signingKeyMethod)
		assert.Equal(t, "my-kid", cfg.signingKeyID)

		cfg.SetSigningKeyGenerator(oidc.NewMockSigningKeyGenerator(t).Execute)
		assert.NotNil(t, cfg.signingKeyGenerator)

		extraGen := oidc.NewMockExtraClaimGenerator(t).Execute
		cfg.SetExtraClaimGenerator(extraGen)
		assert.NotNil(t, cfg.extraClaimGenerator)
	})

	t.Run("error", func(t *testing.T) {
		cfg := NewConfig()
		err := cfg.ValidateConfig()
		assert.ErrorIs(t, err, autherrors.ErrMissingIssuer)

		issGen := oidc.NewMockIssuerGenerator(t).Execute
		cfg.SetIssuerGenerator(issGen)
		cfg.SetExpiresIn(0)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, autherrors.ErrMissingExpiresIn)

		cfg.SetExpiresIn(time.Second * 60)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, autherrors.ErrMissingSigningKey)

		cfg.SetSigningKey([]byte("test"), nil)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, autherrors.ErrMissingSigningKeyMethod)
	})
}
