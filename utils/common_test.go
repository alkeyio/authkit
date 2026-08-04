package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNil(t *testing.T) {
	t.Run("nil_interface", func(t *testing.T) {
		assert.True(t, IsNil(nil))
	})

	t.Run("typed_nil_pointer", func(t *testing.T) {
		var p *int
		assert.True(t, IsNil(p))
	})

	t.Run("typed_nil_slice", func(t *testing.T) {
		var s []string
		assert.True(t, IsNil(s))
	})

	t.Run("typed_nil_map", func(t *testing.T) {
		var m map[string]int
		assert.True(t, IsNil(m))
	})

	t.Run("typed_nil_func", func(t *testing.T) {
		var fn func()
		assert.True(t, IsNil(fn))
	})

	t.Run("typed_nil_chan", func(t *testing.T) {
		var ch chan int
		assert.True(t, IsNil(ch))
	})

	t.Run("non_nil_pointer", func(t *testing.T) {
		v := 42
		assert.False(t, IsNil(&v))
	})

	t.Run("non_nil_slice", func(t *testing.T) {
		assert.False(t, IsNil([]string{"a"}))
	})

	t.Run("non_nil_map", func(t *testing.T) {
		assert.False(t, IsNil(map[string]int{"k": 1}))
	})

	t.Run("non_nil_struct", func(t *testing.T) {
		type S struct{}
		assert.False(t, IsNil(S{}))
	})

	t.Run("non_nil_string", func(t *testing.T) {
		assert.False(t, IsNil("hello"))
	})

	t.Run("non_nil_int", func(t *testing.T) {
		assert.False(t, IsNil(0))
	})
}
