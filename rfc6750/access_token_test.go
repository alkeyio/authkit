package rfc6750

import (
	"context"
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

func newAccessTokenReq() *requests.TokenRequest {
	return &requests.TokenRequest{
		GrantType: types.GrantTypeROPC,
		Client: &sql.Client{
			ClientID: uuid.NewString(),
			Scopes:   []string{"openid", "email", "profile"},
		},
		User:   &sql.User{UserID: uuid.NewString()},
		Scopes: types.NewScopes([]string{"openid", "email", "unknown"}),
	}
}

func TestOpaqueAccessTokenGenerator_Generate(t *testing.T) {
	t.Run("success_with_defaults", func(t *testing.T) {
		r := newAccessTokenReq()
		token := &sql.Token{}

		err := NewOpaqueAccessTokenGenerator().Generate(context.Background(), token, r)
		require.NoError(t, err)
		assert.Equal(t, r.Client.GetClientID(), token.GetClientID())
		assert.Equal(t, r.User.GetUserID(), token.GetUserID())
		assert.Contains(t, token.Scopes, "openid")
		assert.Contains(t, token.Scopes, "email")
		assert.NotContains(t, token.Scopes, "unknown")
		assert.False(t, token.GetIssuedAt().IsZero())
		assert.Equal(t, DefaultAccessTokenExpiresIn, token.GetAccessTokenExpiresIn())
		assert.Equal(t, DefaultTokenLength, len(token.GetAccessToken()))
	})

	t.Run("success_without_user", func(t *testing.T) {
		r := newAccessTokenReq()
		r.User = nil
		token := &sql.Token{}

		err := NewOpaqueAccessTokenGenerator().Generate(context.Background(), token, r)
		require.NoError(t, err)
		assert.Empty(t, token.GetUserID())
	})

	t.Run("success_with_expires_in_generator", func(t *testing.T) {
		r := newAccessTokenReq()
		token := &sql.Token{}
		expected := 10 * time.Minute

		expInGen := mockrfc6750.NewMockExpiresInGenerator(t)
		expInGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*sql.Client")).Return(expected).Once()

		opts := NewTokenGeneratorOptions().SetExpiresInGenerator(expInGen.Execute)
		err := NewOpaqueAccessTokenGenerator(opts).Generate(context.Background(), token, r)
		require.NoError(t, err)
		assert.Equal(t, expected, token.GetAccessTokenExpiresIn())
	})

	t.Run("success_with_rand_string_generator", func(t *testing.T) {
		r := newAccessTokenReq()
		token := &sql.Token{}
		expected := "custom-token-value"

		strGen := mockrfc6750.NewMockRandStringGenerator(t)
		strGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*sql.Client")).Return(expected, nil).Once()

		opts := NewTokenGeneratorOptions().SetRandStringGenerator(strGen.Execute)
		err := NewOpaqueAccessTokenGenerator(opts).Generate(context.Background(), token, r)
		require.NoError(t, err)
		assert.Equal(t, expected, token.GetAccessToken())
	})

	t.Run("error_when_client_is_nil", func(t *testing.T) {
		r := newAccessTokenReq()
		r.Client = nil

		err := NewOpaqueAccessTokenGenerator().Generate(context.Background(), &sql.Token{}, r)
		assert.ErrorIs(t, err, ErrNilClient)
	})

	t.Run("error_when_token_length_is_zero", func(t *testing.T) {
		r := newAccessTokenReq()
		g := NewOpaqueAccessTokenGenerator()
		g.tokenLength = 0

		err := g.Generate(context.Background(), &sql.Token{}, r)
		assert.ErrorIs(t, err, ErrInvalidTokenLength)
	})

	t.Run("error_when_rand_string_generator_fails", func(t *testing.T) {
		r := newAccessTokenReq()
		strGen := mockrfc6750.NewMockRandStringGenerator(t)
		strGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*sql.Client")).Return("", errors.New("entropy error")).Once()

		opts := NewTokenGeneratorOptions().SetRandStringGenerator(strGen.Execute)
		err := NewOpaqueAccessTokenGenerator(opts).Generate(context.Background(), &sql.Token{}, r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "entropy error")
	})
}
