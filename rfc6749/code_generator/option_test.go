package codegen

import (
	"testing"
	"time"

	codegen "github.com/alkeyio/authkit/mocks/rfc6749/code_generator"
	"github.com/stretchr/testify/assert"
)

func TestNewOptions(t *testing.T) {
	opts := NewOptions()
	assert.Equal(t, DefaultCodeLength, opts.codeLength)
	assert.Equal(t, DefaultExpiresIn, opts.expiresIn)
	assert.Nil(t, opts.expiresInGenerator)
	assert.Nil(t, opts.randStringGenerator)
	assert.Nil(t, opts.extraDataGenerator)
}

func TestOptions_Setters(t *testing.T) {
	t.Run("SetCodeLength", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetCodeLength(64)
		assert.Equal(t, 64, opts.codeLength)
		assert.Equal(t, opts, result)
	})

	t.Run("SetExpiresIn", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetExpiresIn(10 * time.Minute)
		assert.Equal(t, 10*time.Minute, opts.expiresIn)
		assert.Equal(t, opts, result)
	})

	t.Run("SetExpiresInGenerator", func(t *testing.T) {
		fn := codegen.NewMockExpiresInGenerator(t).Execute
		opts := NewOptions()
		result := opts.SetExpiresInGenerator(fn)
		assert.NotNil(t, opts.expiresInGenerator)
		assert.Equal(t, opts, result)

		opts.SetExpiresInGenerator(nil)
		assert.Nil(t, opts.expiresInGenerator)
	})

	t.Run("SetRandStringGenerator", func(t *testing.T) {
		fn := codegen.NewMockRandStringGenerator(t).Execute
		opts := NewOptions()
		result := opts.SetRandStringGenerator(fn)
		assert.NotNil(t, opts.randStringGenerator)
		assert.Equal(t, opts, result)

		opts.SetRandStringGenerator(nil)
		assert.Nil(t, opts.randStringGenerator)
	})

	t.Run("SetExtraDataGenerator", func(t *testing.T) {
		fn := codegen.NewMockExtraDataGenerator(t).Execute
		opts := NewOptions()
		result := opts.SetExtraDataGenerator(fn)
		assert.NotNil(t, opts.extraDataGenerator)
		assert.Equal(t, opts, result)

		opts.SetExtraDataGenerator(nil)
		assert.Nil(t, opts.extraDataGenerator)
	})
}
