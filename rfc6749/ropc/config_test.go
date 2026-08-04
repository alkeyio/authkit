package ropc

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/alkeyio/authkit/mocks/rfc6749/ropc"
	"github.com/alkeyio/authkit/types"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	assert.Equal(t, []string{http.MethodPost}, cfg.tokenEndpointHttpMethods)
	assert.Equal(t, map[types.ClientAuthMethod]bool{
		types.ClientBasicAuthentication: true,
	}, cfg.supportedClientAuthMethods)
	assert.Equal(t, OmittedScopePolicyReject, cfg.omittedScopePolicy)
	assert.Empty(t, cfg.tokenReqValidators)
	assert.Empty(t, cfg.tokenProcessors)
	assert.Nil(t, cfg.clientMgr)
	assert.Nil(t, cfg.userMgr)
	assert.Nil(t, cfg.tokenMgr)
}

func TestConfig_Setters(t *testing.T) {
	cfg := NewConfig()

	mockClientMgr := ropc.NewMockClientManager(t)
	cfg.SetClientManager(mockClientMgr)
	assert.Equal(t, mockClientMgr, cfg.clientMgr)

	mockUserMgr := ropc.NewMockUserManager(t)
	cfg.SetUserManager(mockUserMgr)
	assert.Equal(t, mockUserMgr, cfg.userMgr)

	mockTokenMgr := ropc.NewMockTokenManager(t)
	cfg.SetTokenManager(mockTokenMgr)
	assert.Equal(t, mockTokenMgr, cfg.tokenMgr)

	methods := map[types.ClientAuthMethod]bool{types.ClientNoneAuthentication: true}
	cfg.SetSupportedClientAuthMethods(methods)
	assert.Equal(t, methods, cfg.supportedClientAuthMethods)

	cfg.SetTokenEndpointHttpMethods([]string{http.MethodPut})
	assert.Equal(t, []string{http.MethodPut}, cfg.tokenEndpointHttpMethods)

	cfg.SetOmittedScopePolicy(OmittedScopePolicyUseClientDefault)
	assert.Equal(t, OmittedScopePolicyUseClientDefault, cfg.omittedScopePolicy)
}

func TestConfig_RegisterExtension(t *testing.T) {
	t.Run("registers_to_single_slice", func(t *testing.T) {
		cfg := NewConfig()
		cfg.RegisterExtension(ropc.NewMockTokenRequestValidator(t))
		cfg.RegisterExtension(ropc.NewMockTokenProcessor(t))

		assert.Len(t, cfg.tokenReqValidators, 1)
		assert.Len(t, cfg.tokenProcessors, 1)
	})

	t.Run("registers_to_all_matching_slices", func(t *testing.T) {
		type multiExt struct {
			ropc.MockTokenRequestValidator
			ropc.MockTokenProcessor
		}

		cfg := NewConfig()
		cfg.RegisterExtension(&multiExt{})

		assert.Len(t, cfg.tokenReqValidators, 1)
		assert.Len(t, cfg.tokenProcessors, 1)
	})

	t.Run("ignores_non_extension_types", func(t *testing.T) {
		cfg := NewConfig()
		cfg.RegisterExtension(struct{}{})

		assert.Empty(t, cfg.tokenReqValidators)
		assert.Empty(t, cfg.tokenProcessors)
	})
}

func TestConfig_ValidateConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(ropc.NewMockClientManager(t)).
			SetUserManager(ropc.NewMockUserManager(t)).
			SetTokenManager(ropc.NewMockTokenManager(t))
		assert.NoError(t, cfg.ValidateConfig())
	})

	t.Run("error_when_client_manager_nil", func(t *testing.T) {
		cfg := NewConfig()
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilClientManager)
	})

	t.Run("error_when_user_manager_nil", func(t *testing.T) {
		cfg := NewConfig().SetClientManager(ropc.NewMockClientManager(t))
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilUserManager)
	})

	t.Run("error_when_token_manager_nil", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(ropc.NewMockClientManager(t)).
			SetUserManager(ropc.NewMockUserManager(t))
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilTokenManager)
	})

	t.Run("error_when_client_auth_methods_empty", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(ropc.NewMockClientManager(t)).
			SetUserManager(ropc.NewMockUserManager(t)).
			SetTokenManager(ropc.NewMockTokenManager(t)).
			SetSupportedClientAuthMethods(nil)
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrEmptyClientAuthMethods)
	})
}
