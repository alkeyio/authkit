package rfc7636

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateS256CodeChallenge(t *testing.T) {
	t.Run("known_rfc_vector", func(t *testing.T) {
		// RFC 7636 Appendix B test vector
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		assert.Equal(t, expected, CreateS256CodeChallenge(verifier))
	})

	t.Run("idempotent", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		assert.Equal(t, CreateS256CodeChallenge(verifier), CreateS256CodeChallenge(verifier))
	})
}

func TestValidateS256CodeChallengePattern(t *testing.T) {
	t.Run("valid_rfc_vector", func(t *testing.T) {
		assert.True(t, ValidateS256CodeChallengePattern("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
	})

	t.Run("valid_43_chars", func(t *testing.T) {
		assert.True(t, ValidateS256CodeChallengePattern(strings.Repeat("a", 43)))
	})

	t.Run("invalid_too_short", func(t *testing.T) {
		assert.False(t, ValidateS256CodeChallengePattern(strings.Repeat("a", 42)))
	})

	t.Run("invalid_too_long", func(t *testing.T) {
		assert.False(t, ValidateS256CodeChallengePattern(strings.Repeat("a", 44)))
	})

	t.Run("invalid_padding_char", func(t *testing.T) {
		// base64url has no padding; '=' is invalid
		assert.False(t, ValidateS256CodeChallengePattern(strings.Repeat("a", 42)+"="))
	})

	t.Run("invalid_dot_char", func(t *testing.T) {
		// '.' is valid in code_verifier but not in base64url
		assert.False(t, ValidateS256CodeChallengePattern(strings.Repeat("a", 42)+"."))
	})
}

func TestValidateCodeVerifierPattern(t *testing.T) {
	t.Run("valid_min_length", func(t *testing.T) {
		assert.True(t, ValidateCodeVerifierPattern(strings.Repeat("a", 43)))
	})

	t.Run("valid_max_length", func(t *testing.T) {
		assert.True(t, ValidateCodeVerifierPattern(strings.Repeat("a", 128)))
	})

	t.Run("valid_all_allowed_chars", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		assert.True(t, ValidateCodeVerifierPattern(verifier))
	})

	t.Run("invalid_too_short", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(strings.Repeat("a", 42)))
	})

	t.Run("invalid_too_long", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(strings.Repeat("a", 129)))
	})

	t.Run("invalid_chars", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(strings.Repeat("@", 43)))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(""))
	})
}
