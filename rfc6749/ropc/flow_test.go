package ropc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alkeyio/authkit/integrations/sql"
	"github.com/alkeyio/authkit/mocks/rfc6749/ropc"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestFlow_Must(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockClientMgr := ropc.NewMockClientManager(t)
		mockUserMgr := ropc.NewMockUserManager(t)
		mockTokMgr := ropc.NewMockTokenManager(t)

		f, err := Must(NewConfig().SetClientManager(mockClientMgr).SetUserManager(mockUserMgr).SetTokenManager(mockTokMgr))
		require.NoError(t, err)
		assert.NotNil(t, f)
	})

	t.Run("error", func(t *testing.T) {
		f, err := Must(NewConfig().SetClientManager(nil))
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
		{
			types.GrantTypeROPC,
			true,
		},
		{
			types.NewGrantType(""),
			false,
		},
		{
			types.NewGrantType("test"),
			false,
		},
	}

	for i, c := range cases {
		valid := f.CheckGrantType(c.grantType)
		assert.Equalf(t, c.expected, valid, "case %d failed: expected=%t, actual=%t", i, c.expected, valid)
	}
}

func TestFlow_TokenResponse(t *testing.T) {
	mockTokenMgr := ropc.NewMockTokenManager(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr))

	newReq := func() *requests.TokenRequest {
		return &requests.TokenRequest{
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
			Client:    &sql.Client{},
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
		}
	}

	t.Run("success", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		err := f.TokenResponse(newReq(), httptest.NewRecorder())
		assert.NoError(t, err)
	})

	t.Run("error_when_gen_token_fails", func(t *testing.T) {
		mockTokenMgr.On("New").Return(nil).Once()

		err := f.TokenResponse(newReq(), httptest.NewRecorder())
		assert.ErrorIs(t, err, ErrNilToken)
	})

	t.Run("error_when_save_fails", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(errors.New("db error")).Once()

		err := f.TokenResponse(newReq(), httptest.NewRecorder())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
	})
}

func TestFlow_TokenResponse_WithProcessor(t *testing.T) {
	mockTokenMgr := ropc.NewMockTokenManager(t)
	mockProcessor := ropc.NewMockTokenProcessor(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr).RegisterExtension(mockProcessor))

	r := &requests.TokenRequest{
		Client:  &sql.Client{},
		Request: httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
	}

	t.Run("success_processor_called", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()
		mockProcessor.On("ProcessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.NoError(t, err)
	})

	t.Run("error_when_processor_fails", func(t *testing.T) {
		mockToken := &sql.Token{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()
		mockProcessor.On("ProcessToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("processor error")).Once()

		err := f.TokenResponse(r, httptest.NewRecorder())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "processor error")
	})
}

func TestFlow_checkTokenEndpointHttpMethod(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig().SetTokenEndpointHttpMethods([]string{http.MethodDelete, http.MethodPut})
		f := New(cfg)
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPut, "/", nil),
		}
		err := f.checkTokenEndpointHttpMethod(r)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		cfg := NewConfig().SetTokenEndpointHttpMethods([]string{http.MethodDelete})
		f := New(cfg)
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}
		err := f.checkTokenEndpointHttpMethod(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}

func TestFlow_ValidateGrantType(t *testing.T) {
	f := New(NewConfig())
	t.Run("success", func(t *testing.T) {
		r := &requests.TokenRequest{
			GrantType: types.GrantTypeROPC,
		}
		err := f.validateGrantType(r)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		reqs := []*requests.TokenRequest{
			{
				GrantType: "",
			},
			{
				GrantType: "makai",
			},
		}
		for i, r := range reqs {
			err := f.validateGrantType(r)
			assert.Errorf(t, err, "case %d failed: actual=%v", i, err)
		}
	})
}

func TestFlow_checkParams(t *testing.T) {
	f := New(NewConfig())
	t.Run("success", func(t *testing.T) {
		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
		}
		err := f.checkParams(r)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {

		cases := []struct {
			r     *requests.TokenRequest
			error string
		}{
			{
				&requests.TokenRequest{
					Request: httptest.NewRequest(http.MethodDelete, "/", nil),
				},
				"invalid_request",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: "",
				},
				"invalid_request",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: types.GrantTypeAuthorizationCode,
				},
				"unsupported_grant_type",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: types.GrantTypeROPC,
					Username:  "",
				},
				"invalid_request",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: types.GrantTypeROPC,
					Username:  "makai",
					Password:  "",
				},
				"invalid_request",
			},
		}
		for i, c := range cases {
			err := f.checkParams(c.r)
			assert.Error(t, err)
			assert.Containsf(t, err.Error(), c.error, "case %d failed", i)
		}
	})
}

func TestFlow_authenticateClient(t *testing.T) {
	mockClientMgr := ropc.NewMockClientManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr))

	t.Run("success", func(t *testing.T) {
		mockClient := &sql.Client{
			GrantTypes: []string{types.GrantTypeROPC.String()},
		}
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(mockClient, nil).Once()
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}

		err := f.authenticateClient(r)
		assert.NoError(t, err)

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_client_not_found", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_store_returns_error", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, errors.New("unexpected")).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected")

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_grant_type_is_unsupported", func(t *testing.T) {
		mockClient := &sql.Client{
			GrantTypes: []string{},
		}
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(mockClient, nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized_client")

		mockClientMgr.AssertExpectations(t)
	})
}

func TestFlow_authenticateUser(t *testing.T) {
	mockUser := &sql.User{}
	mockUserMgr := ropc.NewMockUserManager(t)
	f := New(NewConfig().SetUserManager(mockUserMgr))

	t.Run("success", func(t *testing.T) {
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(mockUser, nil).Once()
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}

		err := f.authenticateUser(r)
		assert.NoError(t, err)
		assert.Equal(t, mockUser, r.User)

		mockUserMgr.AssertExpectations(t)
	})

	t.Run("error_when_user_not_found", func(t *testing.T) {
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil, nil).Once()
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}

		err := f.authenticateUser(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")

		mockUserMgr.AssertExpectations(t)
	})

	t.Run("error_when_store_returns_error", func(t *testing.T) {
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil, errors.New("unexpected")).Once()
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}

		err := f.authenticateUser(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected")

		mockUserMgr.AssertExpectations(t)
	})
}

func TestFlow_validateScope(t *testing.T) {
	t.Run("policy_reject/error_when_scope_omitted", func(t *testing.T) {
		f := New(NewConfig().SetOmittedScopePolicy(OmittedScopePolicyReject))
		r := &requests.TokenRequest{
			Client: &sql.Client{Scopes: []string{"read", "write"}},
			Scopes: types.Scopes{},
		}
		err := f.validateScope(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
	})

	t.Run("policy_use_client_default/uses_client_scopes_when_omitted", func(t *testing.T) {
		f := New(NewConfig().SetOmittedScopePolicy(OmittedScopePolicyUseClientDefault))
		r := &requests.TokenRequest{
			Client: &sql.Client{Scopes: []string{"read", "write"}},
			Scopes: types.Scopes{},
		}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"read", "write"}, r.Scopes.String())
	})

	t.Run("success_filters_allowed_scopes", func(t *testing.T) {
		f := New(NewConfig())
		r := &requests.TokenRequest{
			Client: &sql.Client{Scopes: []string{"read", "write"}},
			Scopes: types.NewScopes([]string{"read", "write"}),
		}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"read", "write"}, r.Scopes.String())
	})

	t.Run("success_filters_to_allowed_subset", func(t *testing.T) {
		f := New(NewConfig())
		r := &requests.TokenRequest{
			Client: &sql.Client{Scopes: []string{"read"}},
			Scopes: types.NewScopes([]string{"read", "admin"}),
		}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.Equal(t, []string{"read"}, r.Scopes.String())
	})

	t.Run("error_when_all_scopes_denied", func(t *testing.T) {
		f := New(NewConfig())
		r := &requests.TokenRequest{
			Client: &sql.Client{Scopes: []string{"read"}},
			Scopes: types.NewScopes([]string{"admin", "superuser"}),
		}
		err := f.validateScope(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
	})
}

func TestFlow_ValidateTokenRequest(t *testing.T) {
	mockClientMgr := ropc.NewMockClientManager(t)
	mockUserMgr := ropc.NewMockUserManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr).SetUserManager(mockUserMgr))

	validClient := &sql.Client{
		GrantTypes: []string{types.GrantTypeROPC.String()},
		Scopes:     []string{"read"},
	}

	t.Run("success", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(&sql.User{}, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.NoError(t, err)
		assert.Equal(t, validClient, r.Client)

		mockClientMgr.AssertExpectations(t)
		mockUserMgr.AssertExpectations(t)
	})

	t.Run("error_when_check_params_fails", func(t *testing.T) {
		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "",
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_client_auth_fails", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_scope_invalid", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
			Scopes:    types.NewScopes([]string{"admin", "superuser"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_user_auth_fails", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil, nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "wrongpassword",
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")

		mockClientMgr.AssertExpectations(t)
		mockUserMgr.AssertExpectations(t)
	})
}

func TestFlow_ValidateTokenRequest_WithExtension(t *testing.T) {
	mockClientMgr := ropc.NewMockClientManager(t)
	mockUserMgr := ropc.NewMockUserManager(t)
	mockValidator := ropc.NewMockTokenRequestValidator(t)
	f := New(NewConfig().SetClientManager(mockClientMgr).SetUserManager(mockUserMgr).RegisterExtension(mockValidator))

	validClient := &sql.Client{GrantTypes: []string{types.GrantTypeROPC.String()}, Scopes: []string{"read"}}

	t.Run("success_validator_called", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(&sql.User{}, nil).Once()
		mockValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything).Return(nil).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.NoError(t, err)

		mockClientMgr.AssertExpectations(t)
		mockUserMgr.AssertExpectations(t)
		mockValidator.AssertExpectations(t)
	})

	t.Run("error_when_validator_fails", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(validClient, nil).Once()
		mockUserMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(&sql.User{}, nil).Once()
		mockValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything).Return(errors.New("validator error")).Once()

		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/oauth/token", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
			Scopes:    types.NewScopes([]string{"read"}),
		}
		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validator error")

		mockClientMgr.AssertExpectations(t)
		mockUserMgr.AssertExpectations(t)
		mockValidator.AssertExpectations(t)
	})
}

func TestFlow_genToken(t *testing.T) {
	mockToken := &sql.Token{}
	mockTokenMgr := ropc.NewMockTokenManager(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr))

	t.Run("success_without_refresh_token", func(t *testing.T) {
		mockClient := &sql.Client{GrantTypes: []string{types.GrantTypeROPC.String()}}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
			Client:  mockClient,
		}
		tok, err := f.genToken(r)
		assert.NoError(t, err)
		assert.Equal(t, mockToken, tok)

		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("success_with_refresh_token", func(t *testing.T) {
		mockClient := &sql.Client{GrantTypes: []string{types.GrantTypeROPC.String(), types.GrantTypeRefreshToken.String()}}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, true).Return(nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
			Client:  mockClient,
		}
		tok, err := f.genToken(r)
		assert.NoError(t, err)
		assert.Equal(t, mockToken, tok)

		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_new_returns_nil", func(t *testing.T) {
		mockClient := &sql.Client{}
		mockTokenMgr.On("New").Return(nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
			Client:  mockClient,
		}
		tok, err := f.genToken(r)
		assert.ErrorIs(t, err, ErrNilToken)
		assert.Nil(t, tok)

		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_generate_fails", func(t *testing.T) {
		mockClient := &sql.Client{}
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(errors.New("unexpected")).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
			Client:  mockClient,
		}
		tok, err := f.genToken(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected")
		assert.Nil(t, tok)

		mockTokenMgr.AssertExpectations(t)
	})
}
