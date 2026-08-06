package clientcredentials

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alkeyio/authkit/integrations/sql"
	ccmock "github.com/alkeyio/authkit/mocks/rfc6749/client_credentials"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// confidentialClient is a pre-configured sql.Client that passes all
// built-in checks: confidential, permitted to use client_credentials.
func confidentialClient(scopes ...string) *sql.Client {
	return &sql.Client{
		GrantTypes:              []string{types.GrantTypeClientCredentials.String()},
		Scopes:                  scopes,
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

func newTokenRequest(method string) *requests.TokenRequest {
	return &requests.TokenRequest{
		GrantType: types.GrantTypeClientCredentials,
		Request:   httptest.NewRequest(method, "/token", nil),
	}
}

func TestFlow_Must(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f, err := Must(NewConfig().
			SetClientManager(ccmock.NewMockClientManager(t)).
			SetTokenManager(ccmock.NewMockTokenManager(t)))
		require.NoError(t, err)
		assert.NotNil(t, f)
	})

	t.Run("error_when_config_invalid", func(t *testing.T) {
		f, err := Must(NewConfig())
		require.Error(t, err)
		assert.Nil(t, f)
	})
}

func TestFlow_CheckGrantType(t *testing.T) {
	f := New(NewConfig())
	cases := []struct {
		grantType types.GrantType
		expected  bool
	}{
		{types.GrantTypeClientCredentials, true},
		{types.GrantTypeROPC, false},
		{types.NewGrantType(""), false},
		{types.NewGrantType("unknown"), false},
	}

	for i, c := range cases {
		assert.Equalf(t, c.expected, f.CheckGrantType(c.grantType), "case %d", i)
	}
}

func TestFlow_checkTokenEndpointHttpMethod(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := New(NewConfig())
		r := newTokenRequest(http.MethodPost)
		assert.NoError(t, f.checkTokenEndpointHttpMethod(r))
	})

	t.Run("error_when_method_not_allowed", func(t *testing.T) {
		f := New(NewConfig())
		r := newTokenRequest(http.MethodGet)
		err := f.checkTokenEndpointHttpMethod(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("success_with_custom_methods", func(t *testing.T) {
		f := New(NewConfig().SetTokenEndpointHttpMethods([]string{http.MethodPut}))
		r := newTokenRequest(http.MethodPut)
		assert.NoError(t, f.checkTokenEndpointHttpMethod(r))
	})
}

func TestFlow_validateGrantType(t *testing.T) {
	f := New(NewConfig())

	t.Run("success", func(t *testing.T) {
		r := &requests.TokenRequest{GrantType: types.GrantTypeClientCredentials}
		assert.NoError(t, f.validateGrantType(r))
	})

	t.Run("error_when_grant_type_missing", func(t *testing.T) {
		r := &requests.TokenRequest{GrantType: types.NewGrantType("")}
		err := f.validateGrantType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_wrong_grant_type", func(t *testing.T) {
		r := &requests.TokenRequest{GrantType: types.GrantTypeROPC}
		err := f.validateGrantType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported_grant_type")
	})
}

func TestFlow_authenticateClient(t *testing.T) {
	mockClientMgr := ccmock.NewMockClientManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr))

	t.Run("success", func(t *testing.T) {
		client := confidentialClient()
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(client, nil).Once()

		r := newTokenRequest(http.MethodPost)
		err := f.authenticateClient(r)
		assert.NoError(t, err)
		assert.Equal(t, client, r.Client)
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_authenticate_returns_error", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, errors.New("store error")).Once()

		r := newTokenRequest(http.MethodPost)
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "store error")
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_client_not_found", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, nil).Once()

		r := newTokenRequest(http.MethodPost)
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_client_is_public", func(t *testing.T) {
		publicClient := &sql.Client{
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{types.GrantTypeClientCredentials.String()},
		}
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(publicClient, nil).Once()

		r := newTokenRequest(http.MethodPost)
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_grant_type_not_allowed", func(t *testing.T) {
		client := &sql.Client{
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{},
		}
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(client, nil).Once()

		r := newTokenRequest(http.MethodPost)
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized_client")
		mockClientMgr.AssertExpectations(t)
	})
}

func TestFlow_validateScope(t *testing.T) {
	t.Run("policy_reject/error_when_scope_omitted", func(t *testing.T) {
		f := New(NewConfig().SetOmittedScopePolicy(OmittedScopePolicyReject))
		r := &requests.TokenRequest{
			Client: confidentialClient("read", "write"),
			Scopes: types.Scopes{},
		}
		err := f.validateScope(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
	})

	t.Run("policy_use_client_default/uses_client_scopes_when_omitted", func(t *testing.T) {
		f := New(NewConfig().SetOmittedScopePolicy(OmittedScopePolicyUseClientDefault))
		r := &requests.TokenRequest{
			Client: confidentialClient("read", "write"),
			Scopes: types.Scopes{},
		}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"read", "write"}, r.Scopes.String())
	})

	t.Run("success_filters_allowed_scopes", func(t *testing.T) {
		f := New(NewConfig())
		r := &requests.TokenRequest{
			Client: confidentialClient("read", "write"),
			Scopes: types.NewScopes([]string{"read", "write"}),
		}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"read", "write"}, r.Scopes.String())
	})

	t.Run("success_filters_to_allowed_subset", func(t *testing.T) {
		f := New(NewConfig())
		r := &requests.TokenRequest{
			Client: confidentialClient("read"),
			Scopes: types.NewScopes([]string{"read", "admin"}),
		}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.Equal(t, []string{"read"}, r.Scopes.String())
	})

	t.Run("error_when_all_requested_scopes_denied", func(t *testing.T) {
		f := New(NewConfig())
		r := &requests.TokenRequest{
			Client: confidentialClient("read"),
			Scopes: types.NewScopes([]string{"admin", "superuser"}),
		}
		err := f.validateScope(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
	})
}

func TestFlow_genToken(t *testing.T) {
	mockTokenMgr := ccmock.NewMockTokenManager(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr))

	t.Run("success_never_includes_refresh_token", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		// RFC 6749 §4.4.3: refresh token SHOULD NOT be included — always false.
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()

		r := &requests.TokenRequest{
			Client:  confidentialClient(),
			Request: httptest.NewRequest(http.MethodPost, "/token", nil),
		}
		tok, err := f.genToken(r)
		assert.NoError(t, err)
		assert.Equal(t, mockToken, tok)
		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_new_returns_nil", func(t *testing.T) {
		mockTokenMgr.On("New").Return(nil).Once()

		r := &requests.TokenRequest{
			Client:  confidentialClient(),
			Request: httptest.NewRequest(http.MethodPost, "/token", nil),
		}
		tok, err := f.genToken(r)
		assert.ErrorIs(t, err, ErrNilToken)
		assert.Nil(t, tok)
		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_generate_fails", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(errors.New("generate error")).Once()

		r := &requests.TokenRequest{
			Client:  confidentialClient(),
			Request: httptest.NewRequest(http.MethodPost, "/token", nil),
		}
		tok, err := f.genToken(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "generate error")
		assert.Nil(t, tok)
		mockTokenMgr.AssertExpectations(t)
	})
}

func TestFlow_TokenResponse(t *testing.T) {
	mockTokenMgr := ccmock.NewMockTokenManager(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr))

	r := &requests.TokenRequest{
		Client:  confidentialClient(),
		Request: httptest.NewRequest(http.MethodPost, "/token", nil),
	}

	t.Run("success", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.NoError(t, err)
		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_gen_token_fails", func(t *testing.T) {
		mockTokenMgr.On("New").Return(nil).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.ErrorIs(t, err, ErrNilToken)
		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_save_fails", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(errors.New("db error")).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
		mockTokenMgr.AssertExpectations(t)
	})
}

func TestFlow_TokenResponse_WithProcessor(t *testing.T) {
	mockTokenMgr := ccmock.NewMockTokenManager(t)
	mockProcessor := ccmock.NewMockTokenProcessor(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr).RegisterExtension(mockProcessor))

	r := &requests.TokenRequest{
		Client:  confidentialClient(),
		Request: httptest.NewRequest(http.MethodPost, "/token", nil),
	}

	t.Run("success_processor_called", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()
		mockProcessor.On("ProcessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.NoError(t, err)
		mockTokenMgr.AssertExpectations(t)
		mockProcessor.AssertExpectations(t)
	})

	t.Run("error_when_processor_fails", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()
		mockProcessor.On("ProcessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("processor error")).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "processor error")
		mockTokenMgr.AssertExpectations(t)
		mockProcessor.AssertExpectations(t)
	})
}

func TestFlow_ValidateTokenRequest(t *testing.T) {
	mockClientMgr := ccmock.NewMockClientManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr))

	validClient := confidentialClient("read")

	t.Run("success", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/token", nil),
			GrantType: types.GrantTypeClientCredentials,
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.NoError(t, err)
		assert.Equal(t, validClient, r.Client)
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_http_method_invalid", func(t *testing.T) {
		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodGet, "/token", nil),
			GrantType: types.GrantTypeClientCredentials,
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_grant_type_missing", func(t *testing.T) {
		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/token", nil),
			GrantType: types.NewGrantType(""),
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_client_auth_fails", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/token", nil),
			GrantType: types.GrantTypeClientCredentials,
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_scope_invalid", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/token", nil),
			GrantType: types.GrantTypeClientCredentials,
			Scopes:    types.NewScopes([]string{"admin"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
		mockClientMgr.AssertExpectations(t)
	})
}

func TestFlow_ValidateTokenRequest_WithExtension(t *testing.T) {
	mockClientMgr := ccmock.NewMockClientManager(t)
	mockValidator := ccmock.NewMockTokenRequestValidator(t)
	f := New(NewConfig().SetClientManager(mockClientMgr).RegisterExtension(mockValidator))

	validClient := confidentialClient("read")

	t.Run("success_validator_called", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()
		mockValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything).Return(nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/token", nil),
			GrantType: types.GrantTypeClientCredentials,
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.NoError(t, err)
		mockClientMgr.AssertExpectations(t)
		mockValidator.AssertExpectations(t)
	})

	t.Run("error_when_validator_fails", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()
		mockValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything).Return(errors.New("validator error")).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/token", nil),
			GrantType: types.GrantTypeClientCredentials,
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validator error")
		mockClientMgr.AssertExpectations(t)
		mockValidator.AssertExpectations(t)
	})
}
