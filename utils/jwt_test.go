package utils

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hmacKey = []byte("test-secret-key")

func TestNewJWTToken(t *testing.T) {
	t.Run("success_without_kid", func(t *testing.T) {
		tok, err := NewJWTToken(hmacKey, jwt.SigningMethodHS256)
		require.NoError(t, err)
		assert.NotNil(t, tok)
		assert.Empty(t, tok.KeyID())
		assert.Equal(t, jwt.SigningMethodHS256, tok.SigningMethod())
	})

	t.Run("success_with_kid", func(t *testing.T) {
		tok, err := NewJWTToken(hmacKey, jwt.SigningMethodHS256, "my-key-id")
		require.NoError(t, err)
		assert.Equal(t, "my-key-id", tok.KeyID())
	})

	t.Run("error_on_unsupported_method", func(t *testing.T) {
		_, err := NewJWTToken(hmacKey, jwt.SigningMethodNone)
		assert.Error(t, err)
	})
}

func TestJWTToken_Generate(t *testing.T) {
	t.Run("produces_valid_signed_jwt", func(t *testing.T) {
		tok, err := NewJWTToken(hmacKey, jwt.SigningMethodHS256)
		require.NoError(t, err)

		tokenStr, err := tok.Generate(JWTClaim{"sub": "user-1", "iss": "https://example.com"}, JWTHeader{})
		require.NoError(t, err)
		assert.NotEmpty(t, tokenStr)

		parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return hmacKey, nil
		})
		require.NoError(t, err)
		assert.True(t, parsed.Valid)

		claims := parsed.Claims.(jwt.MapClaims)
		assert.Equal(t, "user-1", claims["sub"])
		assert.Equal(t, "https://example.com", claims["iss"])
		assert.NotNil(t, claims["iat"])
	})

	t.Run("iat_is_set_automatically", func(t *testing.T) {
		tok, err := NewJWTToken(hmacKey, jwt.SigningMethodHS256)
		require.NoError(t, err)

		before := time.Now().UTC().Round(time.Second)
		tokenStr, err := tok.Generate(JWTClaim{}, JWTHeader{})
		require.NoError(t, err)

		parsed, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return hmacKey, nil
		})
		claims := parsed.Claims.(jwt.MapClaims)
		iat, err := claims.GetIssuedAt()
		require.NoError(t, err)
		assert.False(t, iat.Before(before))
	})

	t.Run("kid_header_is_set_when_provided", func(t *testing.T) {
		tok, err := NewJWTToken(hmacKey, jwt.SigningMethodHS256, "key-42")
		require.NoError(t, err)

		tokenStr, err := tok.Generate(JWTClaim{}, JWTHeader{})
		require.NoError(t, err)

		parsed, _ := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
			return hmacKey, nil
		})
		assert.Equal(t, "key-42", parsed.Header["kid"])
	})

	t.Run("extra_headers_are_included", func(t *testing.T) {
		tok, err := NewJWTToken(hmacKey, jwt.SigningMethodHS256)
		require.NoError(t, err)

		tokenStr, err := tok.Generate(JWTClaim{}, JWTHeader{"x-custom": "value"})
		require.NoError(t, err)

		parsed, _ := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
			return hmacKey, nil
		})
		assert.Equal(t, "value", parsed.Header["x-custom"])
	})
}

func TestParseSigningKey(t *testing.T) {
	t.Run("hs256_returns_raw_bytes", func(t *testing.T) {
		key, err := ParseSigningKey(hmacKey, jwt.SigningMethodHS256)
		assert.NoError(t, err)
		assert.Equal(t, hmacKey, key)
	})

	t.Run("hs384_returns_raw_bytes", func(t *testing.T) {
		key, err := ParseSigningKey(hmacKey, jwt.SigningMethodHS384)
		assert.NoError(t, err)
		assert.Equal(t, hmacKey, key)
	})

	t.Run("unsupported_method_returns_error", func(t *testing.T) {
		_, err := ParseSigningKey(hmacKey, jwt.SigningMethodNone)
		assert.ErrorIs(t, err, ErrUnsupportedSigningMethod)
	})

	t.Run("rs256_with_invalid_pem_returns_error", func(t *testing.T) {
		_, err := ParseSigningKey([]byte("not-a-pem"), jwt.SigningMethodRS256)
		assert.Error(t, err)
		assert.False(t, strings.Contains(err.Error(), "unsupported"))
	})

	t.Run("es256_with_invalid_pem_returns_error", func(t *testing.T) {
		_, err := ParseSigningKey([]byte("not-a-pem"), jwt.SigningMethodES256)
		assert.Error(t, err)
	})
}
