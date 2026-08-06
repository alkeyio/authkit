package rfc7636

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/alkeyio/authkit/integrations/sql"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
)

// RFC 7636 Appendix B test vector.
const (
	testVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestNew(t *testing.T) {
	t.Run("no_opts_uses_defaults", func(t *testing.T) {
		f := New()
		assert.NotNil(t, f)
		assert.True(t, f.required)
		assert.True(t, f.allowPlain)
	})

	t.Run("with_opts", func(t *testing.T) {
		opts := NewOptions().SetRequired(false)
		f := New(opts)
		assert.False(t, f.required)
	})

	t.Run("nil_opts_uses_defaults", func(t *testing.T) {
		f := New(nil)
		assert.NotNil(t, f)
		assert.True(t, f.required)
	})
}

func TestProofKeyForCodeExchangeFlow_ValidateAuthorizationRequest(t *testing.T) {
	f := New()

	t.Run("no_pkce_params_skips", func(t *testing.T) {
		r := &requests.AuthorizationRequest{}
		assert.NoError(t, f.ValidateAuthorizationRequest(context.Background(), r))
	})

	t.Run("required_public_client_missing_challenge", func(t *testing.T) {
		// RFC 7636 §4.4.1: public client MUST send code_challenge when required=true.
		r := &requests.AuthorizationRequest{
			Client: &sql.Client{TokenEndpointAuthMethod: string(types.ClientNoneAuthentication)},
		}
		err := f.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "this server requires public clients to use PKCE")
	})

	t.Run("required_confidential_client_no_challenge_skips", func(t *testing.T) {
		// Non-public clients are not forced to use PKCE.
		r := &requests.AuthorizationRequest{
			Client: &sql.Client{TokenEndpointAuthMethod: string(types.ClientBasicAuthentication)},
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(context.Background(), r))
	})

	t.Run("only_method_missing_challenge", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		err := f.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_challenge")
	})

	t.Run("unsupported_method", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.NewCodeChallengeMethod("unsupported"),
		}
		err := f.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_challenge_method")
	})

	t.Run("valid_s256", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(context.Background(), r))
	})

	t.Run("valid_plain", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testVerifier,
			CodeChallengeMethod: types.CodeChallengeMethodPlain,
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(context.Background(), r))
	})

	t.Run("valid_challenge_without_method", func(t *testing.T) {
		// No method → defaults to plain; testChallenge passes plain pattern.
		r := &requests.AuthorizationRequest{
			CodeChallenge: testVerifier,
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(context.Background(), r))
	})

	t.Run("invalid_s256_challenge_format", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       "not-a-valid-s256-challenge",
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		err := f.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_challenge")
	})

	t.Run("invalid_plain_challenge_format", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       "too-short",
			CodeChallengeMethod: types.CodeChallengeMethodPlain,
		}
		err := f.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_challenge")
	})

	t.Run("plain_rejected_when_not_allowed", func(t *testing.T) {
		fS256Only := New(NewOptions().SetAllowPlain(false))
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testVerifier,
			CodeChallengeMethod: types.CodeChallengeMethodPlain,
		}
		err := fS256Only.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "plain")
	})

	t.Run("plain_rejected_when_not_allowed_and_method_omitted", func(t *testing.T) {
		// Omitting method defaults to plain — also rejected when allowPlain=false.
		fS256Only := New(NewOptions().SetAllowPlain(false))
		r := &requests.AuthorizationRequest{
			CodeChallenge: testVerifier,
		}
		err := fS256Only.ValidateAuthorizationRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "plain")
	})
}

func TestProofKeyForCodeExchangeFlow_ValidateTokenRequest(t *testing.T) {
	f := New()

	t.Run("required_public_client_no_verifier", func(t *testing.T) {
		r := &requests.TokenRequest{
			Client: &sql.Client{TokenEndpointAuthMethod: string(types.ClientNoneAuthentication)},
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier")
	})

	t.Run("nil_auth_code", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code")
	})

	t.Run("no_challenge_no_verifier_skips", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{},
		}
		assert.NoError(t, f.ValidateTokenRequest(context.Background(), r))
	})

	t.Run("challenge_present_no_verifier", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{CodeChallenge: testChallenge},
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier")
	})

	t.Run("invalid_verifier_pattern", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{CodeChallenge: testChallenge},
			CodeVerifier:     strings.Repeat("@", 43),
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier")
	})

	t.Run("s256_valid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testChallenge,
				CodeChallengeMethod: string(types.CodeChallengeMethodS256),
			},
			CodeVerifier: testVerifier,
		}
		assert.NoError(t, f.ValidateTokenRequest(context.Background(), r))
	})

	t.Run("s256_invalid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testChallenge,
				CodeChallengeMethod: string(types.CodeChallengeMethodS256),
			},
			CodeVerifier: strings.Repeat("a", 43),
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code verifier")
	})

	t.Run("plain_valid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testVerifier,
				CodeChallengeMethod: string(types.CodeChallengeMethodPlain),
			},
			CodeVerifier: testVerifier,
		}
		assert.NoError(t, f.ValidateTokenRequest(context.Background(), r))
	})

	t.Run("plain_invalid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testVerifier,
				CodeChallengeMethod: string(types.CodeChallengeMethodPlain),
			},
			CodeVerifier: strings.Repeat("b", 43),
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code verifier")
	})

	t.Run("verifier_sent_but_no_challenge_in_auth_code", func(t *testing.T) {
		// Auth code was issued without PKCE but client sends code_verifier — reject.
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{},
			CodeVerifier:     testVerifier,
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code was not issued with a \"code_challenge\"")
	})

	t.Run("empty_stored_method_with_challenge_is_rejected", func(t *testing.T) {
		// ProcessAuthorizationCode always stores method explicitly, so an empty
		// stored method with a non-empty challenge indicates tampering — reject.
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge: testVerifier,
				// CodeChallengeMethod intentionally empty (simulates tampering)
			},
			CodeVerifier: testVerifier,
		}
		err := f.ValidateTokenRequest(context.Background(), r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "\"code_challenge_method\" is missing")
	})
}

func TestProofKeyForCodeExchangeFlow_ProcessAuthorizationCode(t *testing.T) {
	f := New()

	t.Run("nil_auth_code", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		err := f.ProcessAuthorizationCode(context.Background(), r, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code")
	})

	t.Run("stores_challenge_and_method", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		authCode := &sql.AuthorizationCode{}
		err := f.ProcessAuthorizationCode(context.Background(), r, authCode, nil)
		require.NoError(t, err)
		assert.Equal(t, testChallenge, authCode.GetCodeChallenge())
		assert.Equal(t, types.CodeChallengeMethodS256, authCode.GetCodeChallengeMethod())
	})

	t.Run("stores_plain_when_method_omitted", func(t *testing.T) {
		// RFC 7636 §4.3: default is plain when code_challenge_method is absent.
		// ProcessAuthorizationCode must store it explicitly to prevent downgrade.
		r := &requests.AuthorizationRequest{
			CodeChallenge: testVerifier,
			// CodeChallengeMethod intentionally empty
		}
		authCode := &sql.AuthorizationCode{}
		err := f.ProcessAuthorizationCode(context.Background(), r, authCode, nil)
		require.NoError(t, err)
		assert.Equal(t, types.CodeChallengeMethodPlain, authCode.GetCodeChallengeMethod())
	})
}
