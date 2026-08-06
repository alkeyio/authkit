package clientcredentials

import (
	"net/http"
	"testing"

	ccmock "github.com/alkeyio/authkit/mocks/rfc6749/client_credentials"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
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
	assert.Nil(t, cfg.tokenMgr)
}

func TestConfig_Setters(t *testing.T) {
	cfg := NewConfig()

	mockClientMgr := ccmock.NewMockClientManager(t)
	cfg.SetClientManager(mockClientMgr)
	assert.Equal(t, mockClientMgr, cfg.clientMgr)

	mockTokenMgr := ccmock.NewMockTokenManager(t)
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
		cfg.RegisterExtension(ccmock.NewMockTokenRequestValidator(t))
		cfg.RegisterExtension(ccmock.NewMockTokenProcessor(t))

		assert.Len(t, cfg.tokenReqValidators, 1)
		assert.Len(t, cfg.tokenProcessors, 1)
	})

	t.Run("registers_to_all_matching_slices", func(t *testing.T) {
		type multiExt struct {
			ccmock.MockTokenRequestValidator
			ccmock.MockTokenProcessor
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
			SetClientManager(ccmock.NewMockClientManager(t)).
			SetTokenManager(ccmock.NewMockTokenManager(t))
		assert.NoError(t, cfg.ValidateConfig())
	})

	t.Run("error_when_client_manager_nil", func(t *testing.T) {
		cfg := NewConfig()
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilClientManager)
	})

	t.Run("error_when_token_manager_nil", func(t *testing.T) {
		cfg := NewConfig().SetClientManager(ccmock.NewMockClientManager(t))
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrNilTokenManager)
	})

	t.Run("error_when_client_auth_methods_empty", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(ccmock.NewMockClientManager(t)).
			SetTokenManager(ccmock.NewMockTokenManager(t)).
			SetSupportedClientAuthMethods(nil)
		assert.ErrorIs(t, cfg.ValidateConfig(), ErrEmptyClientAuthMethods)
	})
}
