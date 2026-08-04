package authorizationcode

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/integrations/sql"
	oidc "github.com/tniah/authkit/mocks/oidc/core/authorization_code"
	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/types"
)

var (
	testKey    = []byte("test-secret")
	testMethod = jwt.SigningMethodHS256
	testIssuer = "https://auth.example.com"
)

func validConfig() *Config {
	return NewConfig().
		SetIssuer(testIssuer).
		SetSigningKey(testKey, testMethod, "kid-1")
}

func newFlow(t *testing.T) *Flow {
	t.Helper()
	f, err := Must(validConfig())
	require.NoError(t, err)
	return f
}

// authReq returns an AuthorizationRequest with the given scopes and a real
// HTTP request (needed when existNonce is configured).
func authReq(scopes ...string) *requests.AuthorizationRequest {
	return &requests.AuthorizationRequest{
		Scopes:  types.NewScopes(scopes),
		Request: httptest.NewRequest("GET", "/authorize", nil),
	}
}

// tokenReq returns a TokenRequest with all required fields set.
func tokenReq() *requests.TokenRequest {
	return &requests.TokenRequest{
		GrantType: types.GrantTypeAuthorizationCode,
		Scopes:    types.NewScopes([]string{"openid"}),
		Client:    &sql.Client{ClientID: "client-1"},
		User:      &sql.User{UserID: "user-1"},
		AuthCode:  &sql.AuthorizationCode{},
		Request:   httptest.NewRequest("POST", "/token", nil),
	}
}

// parseIDToken parses the signed ID Token string and returns its claims.
func parseIDToken(t *testing.T, tokenStr string) jwt.MapClaims {
	t.Helper()
	tok, err := jwt.Parse(tokenStr, func(_ *jwt.Token) (interface{}, error) {
		return testKey, nil
	})
	require.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

func TestNew(t *testing.T) {
	t.Run("must_valid_config", func(t *testing.T) {
		f, err := Must(validConfig())
		require.NoError(t, err)
		assert.NotNil(t, f)
	})

	t.Run("must_invalid_config_returns_error", func(t *testing.T) {
		_, err := Must(NewConfig())
		assert.ErrorIs(t, err, autherrors.ErrMissingIssuer)
	})

	t.Run("new_skips_validation", func(t *testing.T) {
		// New() must not call ValidateConfig, even with an incomplete config.
		f := New(NewConfig())
		assert.NotNil(t, f)
	})
}

func TestFlow_ValidateAuthorizationRequest(t *testing.T) {
	f := newFlow(t)

	t.Run("non_oidc_scope_skips", func(t *testing.T) {
		r := authReq("profile")
		assert.NoError(t, f.ValidateAuthorizationRequest(r))
	})

	t.Run("nonce_required_missing_returns_error", func(t *testing.T) {
		r := authReq("openid")
		err := f.ValidateAuthorizationRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce")
	})

	t.Run("nonce_not_required_no_nonce_ok", func(t *testing.T) {
		f2 := New(validConfig().SetRequireNonce(false))
		r := authReq("openid")
		assert.NoError(t, f2.ValidateAuthorizationRequest(r))
	})

	t.Run("nonce_already_used_returns_error", func(t *testing.T) {
		existNonce := oidc.NewMockExistNonce(t)
		existNonce.EXPECT().Execute(mock.Anything, "my-nonce", mock.Anything).Return(true)

		f2 := New(validConfig().SetExistNonce(existNonce.Execute))
		r := authReq("openid")
		r.Nonce = "my-nonce"
		err := f2.ValidateAuthorizationRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce")
	})

	t.Run("nonce_not_used_ok", func(t *testing.T) {
		existNonce := oidc.NewMockExistNonce(t)
		existNonce.EXPECT().Execute(mock.Anything, "my-nonce", mock.Anything).Return(false)

		f2 := New(validConfig().SetExistNonce(existNonce.Execute))
		r := authReq("openid")
		r.Nonce = "my-nonce"
		assert.NoError(t, f2.ValidateAuthorizationRequest(r))
	})

	t.Run("valid_request_with_nonce", func(t *testing.T) {
		r := authReq("openid", "profile")
		r.Nonce = "nonce-1"
		assert.NoError(t, f.ValidateAuthorizationRequest(r))
	})
}

func TestFlow_ValidateConsentRequest(t *testing.T) {
	// Use SetRequireNonce(false) throughout so nonce absence does not
	// interfere with consent-specific assertions.
	cfg := validConfig().SetRequireNonce(false)

	t.Run("non_oidc_scope_skips", func(t *testing.T) {
		f := New(cfg)
		r := authReq("profile")
		assert.NoError(t, f.ValidateConsentRequest(r))
	})

	t.Run("nil_user_no_prompts_defaults_to_login", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		// No prompts, nil user — should default to [login] and return nil
		// so the handler can redirect to the login page.
		err := f.ValidateConsentRequest(r)
		require.NoError(t, err)
		assert.Equal(t, types.Prompts{types.PromptLogin}, r.Prompts)
	})

	t.Run("nil_user_prompt_login_returns_nil", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.Prompts = types.NewPrompts([]string{"login"})
		assert.NoError(t, f.ValidateConsentRequest(r))
	})

	t.Run("nil_user_prompt_none_returns_login_required", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.Prompts = types.NewPrompts([]string{"none"})
		err := f.ValidateConsentRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "login_required")
	})

	t.Run("nil_user_prompt_consent_returns_consent_required", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.Prompts = types.NewPrompts([]string{"consent"})
		err := f.ValidateConsentRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "consent_required")
	})

	t.Run("nil_user_prompt_select_account_returns_account_selection_required", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.Prompts = types.NewPrompts([]string{"select_account"})
		err := f.ValidateConsentRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "account_selection_required")
	})

	t.Run("authenticated_user_returns_nil", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.User = &sql.User{UserID: "user-1"}
		assert.NoError(t, f.ValidateConsentRequest(r))
	})

	t.Run("prompt_none_combined_with_other_returns_error", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.Prompts = types.NewPrompts([]string{"none", "login"})
		err := f.ValidateConsentRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "none")
	})

	t.Run("prompt_login_resets_max_age_to_zero", func(t *testing.T) {
		f := New(cfg)
		r := authReq("openid")
		r.User = &sql.User{UserID: "user-1"}
		r.Prompts = types.NewPrompts([]string{"login"})
		require.NoError(t, f.ValidateConsentRequest(r))
		require.NotNil(t, r.MaxAge)
		assert.Equal(t, uint(0), *r.MaxAge)
	})
}

func TestFlow_ProcessAuthorizationCode(t *testing.T) {
	f := newFlow(t)
	r := authReq("openid")

	t.Run("nil_auth_code_returns_error", func(t *testing.T) {
		err := f.ProcessAuthorizationCode(r, nil, nil)
		assert.ErrorIs(t, err, ErrNilAuthorizationCode)
	})

	t.Run("stores_nonce_from_request", func(t *testing.T) {
		r.Nonce = "my-nonce"
		authCode := &sql.AuthorizationCode{}
		require.NoError(t, f.ProcessAuthorizationCode(r, authCode, nil))
		assert.Equal(t, "my-nonce", authCode.GetNonce())
	})

	t.Run("empty_nonce_stored_as_empty", func(t *testing.T) {
		r.Nonce = ""
		authCode := &sql.AuthorizationCode{}
		require.NoError(t, f.ProcessAuthorizationCode(r, authCode, nil))
		assert.Equal(t, "", authCode.GetNonce())
	})
}

func TestFlow_ProcessToken(t *testing.T) {
	f := newFlow(t)

	t.Run("non_oidc_scope_skips", func(t *testing.T) {
		r := tokenReq()
		r.Scopes = types.NewScopes([]string{"profile"})
		data := map[string]interface{}{}
		require.NoError(t, f.ProcessToken(r, nil, data))
		assert.NotContains(t, data, "id_token")
	})

	t.Run("nil_auth_code_returns_error", func(t *testing.T) {
		r := tokenReq()
		r.AuthCode = nil
		err := f.ProcessToken(r, nil, map[string]interface{}{})
		assert.ErrorIs(t, err, ErrNilAuthorizationCode)
	})

	t.Run("nil_user_returns_error", func(t *testing.T) {
		r := tokenReq()
		r.User = nil
		err := f.ProcessToken(r, nil, map[string]interface{}{})
		assert.ErrorIs(t, err, ErrMissingUserID)
	})

	t.Run("empty_user_id_returns_error", func(t *testing.T) {
		r := tokenReq()
		r.User = &sql.User{UserID: ""}
		err := f.ProcessToken(r, nil, map[string]interface{}{})
		assert.ErrorIs(t, err, ErrMissingUserID)
	})

	t.Run("id_token_added_to_data", func(t *testing.T) {
		r := tokenReq()
		data := map[string]interface{}{}
		require.NoError(t, f.ProcessToken(r, nil, data))
		assert.Contains(t, data, "id_token")
	})

	t.Run("id_token_contains_required_claims", func(t *testing.T) {
		r := tokenReq()
		data := map[string]interface{}{}
		require.NoError(t, f.ProcessToken(r, nil, data))

		claims := parseIDToken(t, data["id_token"].(string))
		assert.Equal(t, testIssuer, claims["iss"])
		assert.Equal(t, "user-1", claims["sub"])
		assert.Equal(t, "client-1", claims["aud"].([]interface{})[0])
		assert.NotNil(t, claims["exp"])
		assert.NotNil(t, claims["iat"])
		assert.NotNil(t, claims["auth_time"])
	})

	t.Run("nonce_included_when_present_in_auth_code", func(t *testing.T) {
		r := tokenReq()
		r.AuthCode = &sql.AuthorizationCode{Nonce: "my-nonce"}
		data := map[string]interface{}{}
		require.NoError(t, f.ProcessToken(r, nil, data))

		claims := parseIDToken(t, data["id_token"].(string))
		assert.Equal(t, "my-nonce", claims["nonce"])
	})

	t.Run("nonce_absent_when_not_in_auth_code", func(t *testing.T) {
		r := tokenReq()
		r.AuthCode = &sql.AuthorizationCode{}
		data := map[string]interface{}{}
		require.NoError(t, f.ProcessToken(r, nil, data))

		claims := parseIDToken(t, data["id_token"].(string))
		assert.NotContains(t, claims, "nonce")
	})

	t.Run("auth_time_falls_back_to_now_when_zero", func(t *testing.T) {
		r := tokenReq()
		before := time.Now().UTC().Round(time.Second)
		data := map[string]interface{}{}
		require.NoError(t, f.ProcessToken(r, nil, data))

		claims := parseIDToken(t, data["id_token"].(string))
		authTime := time.Unix(int64(claims["auth_time"].(float64)), 0).UTC()
		assert.False(t, authTime.Before(before))
	})

	t.Run("extra_claims_merged_into_id_token", func(t *testing.T) {
		gen := oidc.NewMockExtraClaimGenerator(t)
		gen.EXPECT().Execute(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(map[string]interface{}{"custom": "value"}, nil)

		f2 := New(validConfig().SetExtraClaimGenerator(gen.Execute))
		r := tokenReq()
		data := map[string]interface{}{}
		require.NoError(t, f2.ProcessToken(r, nil, data))

		claims := parseIDToken(t, data["id_token"].(string))
		assert.Equal(t, "value", claims["custom"])
	})

	t.Run("extra_claims_cannot_override_standard_claims", func(t *testing.T) {
		gen := oidc.NewMockExtraClaimGenerator(t)
		gen.EXPECT().Execute(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(map[string]interface{}{
				"iss":   "malicious-issuer",
				"sub":   "malicious-sub",
				"nonce": "fake-nonce",
			}, nil)

		f2 := New(validConfig().SetExtraClaimGenerator(gen.Execute))
		r := tokenReq()
		r.AuthCode = &sql.AuthorizationCode{Nonce: "real-nonce"}
		data := map[string]interface{}{}
		require.NoError(t, f2.ProcessToken(r, nil, data))

		claims := parseIDToken(t, data["id_token"].(string))
		assert.Equal(t, testIssuer, claims["iss"])
		assert.Equal(t, "user-1", claims["sub"])
		assert.Equal(t, "real-nonce", claims["nonce"])
	})

	t.Run("extra_claim_generator_error_propagates", func(t *testing.T) {
		gen := oidc.NewMockExtraClaimGenerator(t)
		gen.EXPECT().Execute(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, errors.New("generator error"))

		f2 := New(validConfig().SetExtraClaimGenerator(gen.Execute))
		r := tokenReq()
		err := f2.ProcessToken(r, nil, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "generator error")
	})

	t.Run("signing_key_generator_takes_precedence", func(t *testing.T) {
		gen := oidc.NewMockSigningKeyGenerator(t)
		gen.EXPECT().Execute(mock.Anything, mock.Anything).
			Return(testKey, testMethod, "dynamic-kid", nil)

		// Config has no static key; generator provides it.
		f2 := New(NewConfig().SetIssuer(testIssuer).SetSigningKeyGenerator(gen.Execute))
		r := tokenReq()
		data := map[string]interface{}{}
		require.NoError(t, f2.ProcessToken(r, nil, data))
		assert.Contains(t, data, "id_token")
	})

	t.Run("signing_key_generator_error_propagates", func(t *testing.T) {
		gen := oidc.NewMockSigningKeyGenerator(t)
		gen.EXPECT().Execute(mock.Anything, mock.Anything).
			Return(nil, nil, "", errors.New("key error"))

		f2 := New(NewConfig().SetIssuer(testIssuer).SetSigningKeyGenerator(gen.Execute))
		r := tokenReq()
		err := f2.ProcessToken(r, nil, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key error")
	})
}
