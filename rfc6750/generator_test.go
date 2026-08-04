package rfc6750

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authkit/integrations/sql"
	"github.com/tniah/authkit/mocks/rfc6750"
	"github.com/tniah/authkit/requests"
)

func TestMustBearerTokenGenerator(t *testing.T) {
	t.Run("success_with_nil_opts_uses_defaults", func(t *testing.T) {
		g, err := MustBearerTokenGenerator(nil)
		assert.NoError(t, err)
		assert.NotNil(t, g)
	})

	t.Run("error_when_access_token_generator_nil", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions().SetAccessTokenGenerator(nil)
		g, err := MustBearerTokenGenerator(opts)
		assert.ErrorIs(t, err, ErrNilAccessTokenGenerator)
		assert.Nil(t, g)
	})

	t.Run("error_when_refresh_token_generator_nil", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions().SetRefreshTokenGenerator(nil)
		g, err := MustBearerTokenGenerator(opts)
		assert.ErrorIs(t, err, ErrNilRefreshTokenGenerator)
		assert.Nil(t, g)
	})
}

func TestTestBearerTokenGenerator(t *testing.T) {
	g := NewBearerTokenGenerator()
	atGenerator := rfc6750.NewMockTokenGenerator(t)
	atGenerator.On(
		"Generate",
		mock.AnythingOfType("*sql.Token"),
		mock.AnythingOfType("*requests.TokenRequest"),
	).Return(nil).Once()
	g.SetAccessTokenGenerator(atGenerator)

	rtGenerator := rfc6750.NewMockTokenGenerator(t)
	rtGenerator.On(
		"Generate",
		mock.AnythingOfType("*sql.Token"),
		mock.AnythingOfType("*requests.TokenRequest"),
	).Return(nil).Once()
	g.SetRefreshTokenGenerator(rtGenerator)

	mockToken := &sql.Token{}
	r := &requests.TokenRequest{
		GrantType: "password",
	}
	err := g.Generate(mockToken, r, true)
	assert.NoError(t, err)
	assert.Equal(t, TokenTypeBearer, mockToken.GetType())
}
