package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandRune(t *testing.T) {
	t.Run("returns_correct_length", func(t *testing.T) {
		seq, err := GenerateRandRune(32, AlphaNum)
		assert.NoError(t, err)
		assert.Len(t, seq, 32)
	})

	t.Run("uses_only_charset_characters", func(t *testing.T) {
		charset := AlphaNum
		allowed := make(map[rune]bool, len(charset))
		for _, r := range charset {
			allowed[r] = true
		}

		seq, err := GenerateRandRune(128, charset)
		assert.NoError(t, err)
		for _, r := range seq {
			assert.True(t, allowed[r], "unexpected rune %q not in charset", r)
		}
	})

	t.Run("produces_different_results", func(t *testing.T) {
		a, _ := GenerateRandRune(32, AlphaNum)
		b, _ := GenerateRandRune(32, AlphaNum)
		assert.NotEqual(t, a, b)
	})
}

func TestGenerateRandString(t *testing.T) {
	t.Run("returns_correct_length", func(t *testing.T) {
		s, err := GenerateRandString(48, AlphaNum)
		assert.NoError(t, err)
		assert.Len(t, []rune(s), 48)
	})

	t.Run("uses_only_charset_characters", func(t *testing.T) {
		charset := SecretCharset
		allowed := make(map[rune]bool, len(charset))
		for _, r := range charset {
			allowed[r] = true
		}

		s, err := GenerateRandString(256, charset)
		assert.NoError(t, err)
		for _, r := range s {
			assert.True(t, allowed[r], "unexpected rune %q not in charset", r)
		}
	})

	t.Run("produces_different_results", func(t *testing.T) {
		a, _ := GenerateRandString(32, AlphaNum)
		b, _ := GenerateRandString(32, AlphaNum)
		assert.NotEqual(t, a, b)
	})
}
