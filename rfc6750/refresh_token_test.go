package rfc6750

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/alkeyio/authkit/integrations/sql"
	mockrfc6750 "github.com/alkeyio/authkit/mocks/rfc6750"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
)

func newRefreshTokenReq() *requests.TokenRequest {
	return &requests.TokenRequest{
		GrantType: types.GrantTypeAuthorizationCode,
		Client:    &sql.Client{ClientID: uuid.NewString()},
	}
}

func TestOpaqueRefreshTokenGenerator_Generate(t *testing.T) {
	t.Run("success_with_defaults", func(t *testing.T) {
		r := newRefreshTokenReq()
		token := &sql.Token{}

		err := NewOpaqueRefreshTokenGenerator().Generate(token, r)
		require.NoError(t, err)
		assert.Equal(t, DefaultTokenLength, len(token.GetRefreshToken()))
		assert.Equal(t, DefaultRefreshTokenExpiresIn, token.GetRefreshTokenExpiresIn())
	})

	t.Run("success_with_expires_in_generator", func(t *testing.T) {
		r := newRefreshTokenReq()
		token := &sql.Token{}
		expected := 7 * 24 * time.Hour

		expInGen := mockrfc6750.NewMockExpiresInGenerator(t)
		expInGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*sql.Client")).Return(expected).Once()

		opts := NewTokenGeneratorOptions().SetExpiresInGenerator(expInGen.Execute)
		err := NewOpaqueRefreshTokenGenerator(opts).Generate(token, r)
		require.NoError(t, err)
		assert.Equal(t, expected, token.GetRefreshTokenExpiresIn())
	})

	t.Run("success_with_rand_string_generator", func(t *testing.T) {
		r := newRefreshTokenReq()
		token := &sql.Token{}
		expected := "custom-refresh-token"

		strGen := mockrfc6750.NewMockRandStringGenerator(t)
		strGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*sql.Client")).Return(expected, nil).Once()

		opts := NewTokenGeneratorOptions().SetRandStringGenerator(strGen.Execute)
		err := NewOpaqueRefreshTokenGenerator(opts).Generate(token, r)
		require.NoError(t, err)
		assert.Equal(t, expected, token.GetRefreshToken())
	})

	t.Run("error_when_client_is_nil", func(t *testing.T) {
		r := newRefreshTokenReq()
		r.Client = nil

		err := NewOpaqueRefreshTokenGenerator().Generate(&sql.Token{}, r)
		assert.ErrorIs(t, err, ErrNilClient)
	})

	t.Run("error_when_token_length_is_zero", func(t *testing.T) {
		r := newRefreshTokenReq()
		g := NewOpaqueRefreshTokenGenerator()
		g.tokenLength = 0

		err := g.Generate(&sql.Token{}, r)
		assert.ErrorIs(t, err, ErrInvalidTokenLength)
	})

	t.Run("error_when_rand_string_generator_fails", func(t *testing.T) {
		r := newRefreshTokenReq()
		strGen := mockrfc6750.NewMockRandStringGenerator(t)
		strGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*sql.Client")).Return("", errors.New("entropy error")).Once()

		opts := NewTokenGeneratorOptions().SetRandStringGenerator(strGen.Execute)
		err := NewOpaqueRefreshTokenGenerator(opts).Generate(&sql.Token{}, r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "entropy error")
	})
}
