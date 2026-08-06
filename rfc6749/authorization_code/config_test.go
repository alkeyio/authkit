package authorizationcode

import (
	"net/http"
	"testing"

	authcodemock "github.com/alkeyio/authkit/mocks/rfc6749/authorization_code"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	assert.Equal(t, []string{http.MethodGet}, cfg.authEndpointHttpMethods)
	assert.Equal(t, []string{http.MethodPost}, cfg.tokenEndpointHttpMethods)
	assert.Equal(t, map[types.ClientAuthMethod]bool{
		types.ClientBasicAuthentication: true,
		types.ClientNoneAuthentication:  true,
	}, cfg.supportedClientAuthMethods)
	assert.Equal(t, OmittedScopePolicyReject, cfg.omittedScopePolicy)
	assert.Empty(t, cfg.authReqValidators)
	assert.Empty(t, cfg.consentReqValidators)
	assert.Empty(t, cfg.authCodeProcessors)
	assert.Empty(t, cfg.tokenReqValidators)
	assert.Empty(t, cfg.tokenProcessors)
	assert.Nil(t, cfg.clientMgr)
	assert.Nil(t, cfg.userMgr)
	assert.Nil(t, cfg.authCodeMgr)
	assert.Nil(t, cfg.tokenMgr)
}

func TestConfig_Setters(t *testing.T) {
	cfg := NewConfig()

	mockClientMgr := authcodemock.NewMockClientManager(t)
	cfg.SetClientManager(mockClientMgr)
	assert.Equal(t, mockClientMgr, cfg.clientMgr)

	mockUserMgr := authcodemock.NewMockUserManager(t)
	cfg.SetUserManager(mockUserMgr)
	assert.Equal(t, mockUserMgr, cfg.userMgr)

	mockAuthCodeMgr := authcodemock.NewMockAuthCodeManager(t)
	cfg.SetAuthCodeManager(mockAuthCodeMgr)
	assert.Equal(t, mockAuthCodeMgr, cfg.authCodeMgr)

	mockTokenMgr := authcodemock.NewMockTokenManager(t)
	cfg.SetTokenManager(mockTokenMgr)
	assert.Equal(t, mockTokenMgr, cfg.tokenMgr)

	cfg.SetAuthEndpointHttpMethods([]string{http.MethodGet, http.MethodPost})
	assert.Equal(t, []string{http.MethodGet, http.MethodPost}, cfg.authEndpointHttpMethods)

	cfg.SetTokenEndpointHttpMethods([]string{http.MethodPut})
	assert.Equal(t, []string{http.MethodPut}, cfg.tokenEndpointHttpMethods)

	methods := map[types.ClientAuthMethod]bool{types.ClientPostAuthentication: true}
	cfg.SetSupportedClientAuthMethods(methods)
	assert.Equal(t, methods, cfg.supportedClientAuthMethods)

	cfg.SetOmittedScopePolicy(OmittedScopePolicyUseClientDefault)
	assert.Equal(t, OmittedScopePolicyUseClientDefault, cfg.omittedScopePolicy)
}

func TestConfig_RegisterExtension(t *testing.T) {
	t.Run("registers_to_single_slice", func(t *testing.T) {
		cfg := NewConfig()
		cfg.RegisterExtension(authcodemock.NewMockAuthorizationRequestValidator(t))
		cfg.RegisterExtension(authcodemock.NewMockConsentRequestValidator(t))
		cfg.RegisterExtension(authcodemock.NewMockAuthCodeProcessor(t))
		cfg.RegisterExtension(authcodemock.NewMockTokenRequestValidator(t))
		cfg.RegisterExtension(authcodemock.NewMockTokenProcessor(t))

		assert.Len(t, cfg.authReqValidators, 1)
		assert.Len(t, cfg.consentReqValidators, 1)
		assert.Len(t, cfg.authCodeProcessors, 1)
		assert.Len(t, cfg.tokenReqValidators, 1)
		assert.Len(t, cfg.tokenProcessors, 1)
	})

	t.Run("registers_to_all_matching_slices", func(t *testing.T) {
		// multiExt implements all 5 extension interfaces at once.
		type multiExt struct {
			authcodemock.MockAuthorizationRequestValidator
			authcodemock.MockConsentRequestValidator
			authcodemock.MockAuthCodeProcessor
			authcodemock.MockTokenRequestValidator
			authcodemock.MockTokenProcessor
		}

		cfg := NewConfig()
		cfg.RegisterExtension(&multiExt{})

		assert.Len(t, cfg.authReqValidators, 1)
		assert.Len(t, cfg.consentReqValidators, 1)
		assert.Len(t, cfg.authCodeProcessors, 1)
		assert.Len(t, cfg.tokenReqValidators, 1)
		assert.Len(t, cfg.tokenProcessors, 1)
	})

	t.Run("ignores_non_extension_types", func(t *testing.T) {
		cfg := NewConfig()
		cfg.RegisterExtension(struct{}{})

		assert.Empty(t, cfg.authReqValidators)
		assert.Empty(t, cfg.consentReqValidators)
		assert.Empty(t, cfg.authCodeProcessors)
		assert.Empty(t, cfg.tokenReqValidators)
		assert.Empty(t, cfg.tokenProcessors)
	})
}

func TestConfig_ValidateConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(authcodemock.NewMockClientManager(t)).
			SetUserManager(authcodemock.NewMockUserManager(t)).
			SetAuthCodeManager(authcodemock.NewMockAuthCodeManager(t)).
			SetTokenManager(authcodemock.NewMockTokenManager(t))
		assert.NoError(t, cfg.ValidateConfig())
	})

	t.Run("error_when_client_manager_nil", func(t *testing.T) {
		cfg := NewConfig()
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilClientManager)
	})

	t.Run("error_when_user_manager_nil", func(t *testing.T) {
		cfg := NewConfig().SetClientManager(authcodemock.NewMockClientManager(t))
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilUserManager)
	})

	t.Run("error_when_auth_code_manager_nil", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(authcodemock.NewMockClientManager(t)).
			SetUserManager(authcodemock.NewMockUserManager(t))
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilAuthCodeManager)
	})

	t.Run("error_when_token_manager_nil", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(authcodemock.NewMockClientManager(t)).
			SetUserManager(authcodemock.NewMockUserManager(t)).
			SetAuthCodeManager(authcodemock.NewMockAuthCodeManager(t))
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilTokenManager)
	})

	t.Run("error_when_client_auth_methods_empty", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(authcodemock.NewMockClientManager(t)).
			SetUserManager(authcodemock.NewMockUserManager(t)).
			SetAuthCodeManager(authcodemock.NewMockAuthCodeManager(t)).
			SetTokenManager(authcodemock.NewMockTokenManager(t)).
			SetSupportedClientAuthMethods(nil)
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrEmptyClientAuthMethods)
	})
}
