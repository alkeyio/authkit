package rfc6750

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	mockrfc6750 "github.com/alkeyio/authkit/mocks/rfc6750"
)

func TestNewBearerTokenGeneratorOptions(t *testing.T) {
	opts := NewBearerTokenGeneratorOptions()
	assert.NotNil(t, opts.atGen)
	assert.NotNil(t, opts.rfGen)
}

func TestBearerTokenGeneratorOptions_SetAccessTokenGenerator(t *testing.T) {
	t.Run("sets_generator", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		gen := mockrfc6750.NewMockTokenGenerator(t)
		result := opts.SetAccessTokenGenerator(gen)
		assert.Equal(t, opts, result)
		assert.Equal(t, gen, opts.atGen)
	})

	t.Run("clears_generator_when_nil", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		opts.SetAccessTokenGenerator(nil)
		assert.Nil(t, opts.atGen)
	})
}

func TestBearerTokenGeneratorOptions_SetRefreshTokenGenerator(t *testing.T) {
	t.Run("sets_generator", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		gen := mockrfc6750.NewMockTokenGenerator(t)
		result := opts.SetRefreshTokenGenerator(gen)
		assert.Equal(t, opts, result)
		assert.Equal(t, gen, opts.rfGen)
	})

	t.Run("clears_generator_when_nil", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		opts.SetRefreshTokenGenerator(nil)
		assert.Nil(t, opts.rfGen)
	})
}

func TestBearerTokenGeneratorOptions_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		assert.NoError(t, opts.Validate())
	})

	t.Run("error_when_access_token_generator_nil", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		opts.SetAccessTokenGenerator(nil)
		assert.ErrorIs(t, opts.Validate(), ErrNilAccessTokenGenerator)
	})

	t.Run("error_when_refresh_token_generator_nil", func(t *testing.T) {
		opts := NewBearerTokenGeneratorOptions()
		opts.SetRefreshTokenGenerator(nil)
		assert.ErrorIs(t, opts.Validate(), ErrNilRefreshTokenGenerator)
	})
}

func TestNewTokenGeneratorOptions(t *testing.T) {
	opts := NewTokenGeneratorOptions()
	assert.Equal(t, DefaultTokenLength, opts.tokenLength)
	assert.Equal(t, DefaultExpiresIn, opts.expiresIn)
	assert.Nil(t, opts.expiresInGenerator)
	assert.Nil(t, opts.randStringGenerator)
}

func TestTokenGeneratorOptions_Setters(t *testing.T) {
	t.Run("set_token_length", func(t *testing.T) {
		opts := NewTokenGeneratorOptions()
		result := opts.SetTokenLength(64)
		assert.Equal(t, opts, result)
		assert.Equal(t, 64, opts.tokenLength)
	})

	t.Run("set_expires_in", func(t *testing.T) {
		opts := NewTokenGeneratorOptions()
		result := opts.SetExpiresIn(30 * time.Minute)
		assert.Equal(t, opts, result)
		assert.Equal(t, 30*time.Minute, opts.expiresIn)
	})

	t.Run("set_expires_in_generator", func(t *testing.T) {
		opts := NewTokenGeneratorOptions()
		fn := mockrfc6750.NewMockExpiresInGenerator(t).Execute
		result := opts.SetExpiresInGenerator(fn)
		assert.Equal(t, opts, result)
		assert.NotNil(t, opts.expiresInGenerator)
	})

	t.Run("clear_expires_in_generator", func(t *testing.T) {
		opts := NewTokenGeneratorOptions()
		opts.SetExpiresInGenerator(mockrfc6750.NewMockExpiresInGenerator(t).Execute)
		opts.SetExpiresInGenerator(nil)
		assert.Nil(t, opts.expiresInGenerator)
	})

	t.Run("set_rand_string_generator", func(t *testing.T) {
		opts := NewTokenGeneratorOptions()
		fn := mockrfc6750.NewMockRandStringGenerator(t).Execute
		result := opts.SetRandStringGenerator(fn)
		assert.Equal(t, opts, result)
		assert.NotNil(t, opts.randStringGenerator)
	})

	t.Run("clear_rand_string_generator", func(t *testing.T) {
		opts := NewTokenGeneratorOptions()
		opts.SetRandStringGenerator(mockrfc6750.NewMockRandStringGenerator(t).Execute)
		opts.SetRandStringGenerator(nil)
		assert.Nil(t, opts.randStringGenerator)
	})
}
