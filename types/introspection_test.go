package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenTypeHint(t *testing.T) {
	h := NewTokenTypeHint("custom")
	assert.IsType(t, TokenTypeHint(""), h)
	assert.Equal(t, "custom", h.String())
	assert.False(t, h.IsEmpty())
	assert.True(t, NewTokenTypeHint("").IsEmpty())
	assert.False(t, h.IsAccessToken())
	assert.False(t, h.IsRefreshToken())
	assert.False(t, h.IsValid())

	assert.True(t, TokenTypeHintAccessToken.IsAccessToken())
	assert.False(t, TokenTypeHintAccessToken.IsRefreshToken())
	assert.True(t, TokenTypeHintAccessToken.IsValid())

	assert.True(t, TokenTypeHintRefreshToken.IsRefreshToken())
	assert.False(t, TokenTypeHintRefreshToken.IsAccessToken())
	assert.True(t, TokenTypeHintRefreshToken.IsValid())
}
