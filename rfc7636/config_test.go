package rfc7636

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewOptions(t *testing.T) {
	opts := NewOptions()
	assert.True(t, opts.required)
	assert.True(t, opts.allowPlain)
}

func TestOptions_SetRequired(t *testing.T) {
	t.Run("sets_true", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetRequired(true)
		assert.Equal(t, opts, result)
		assert.True(t, opts.required)
	})

	t.Run("sets_false", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetRequired(false)
		assert.Equal(t, opts, result)
		assert.False(t, opts.required)
	})
}

func TestOptions_SetAllowPlain(t *testing.T) {
	t.Run("sets_true", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetAllowPlain(true)
		assert.Equal(t, opts, result)
		assert.True(t, opts.allowPlain)
	})

	t.Run("sets_false", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetAllowPlain(false)
		assert.Equal(t, opts, result)
		assert.False(t, opts.allowPlain)
	})
}
