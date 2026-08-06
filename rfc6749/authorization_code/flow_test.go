package authorizationcode

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/alkeyio/authkit/integrations/sql"
	authcodemock "github.com/alkeyio/authkit/mocks/rfc6749/authorization_code"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
)

func newAuthReq(method string) *requests.AuthorizationRequest {
	return &requests.AuthorizationRequest{
		Request: httptest.NewRequest(method, "/authorize", nil),
	}
}

func newTokenReq() *requests.TokenRequest {
	return &requests.TokenRequest{
		Request: httptest.NewRequest(http.MethodPost, "/token", nil),
	}
}

func validClient() *sql.Client {
	return &sql.Client{
		ClientID:      "client-1",
		RedirectURIs:  []string{"https://example.com/cb"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"read", "write"},
	}
}

func TestFlow_Must(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig().
			SetClientManager(authcodemock.NewMockClientManager(t)).
			SetUserManager(authcodemock.NewMockUserManager(t)).
			SetAuthCodeManager(authcodemock.NewMockAuthCodeManager(t)).
			SetTokenManager(authcodemock.NewMockTokenManager(t))

		f, err := Must(cfg)
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
		gt       types.GrantType
		expected bool
	}{
		{types.GrantTypeAuthorizationCode, true},
		{types.GrantTypeROPC, false},
		{types.GrantTypeRefreshToken, false},
		{types.NewGrantType(""), false},
	}
	for i, c := range cases {
		assert.Equalf(t, c.expected, f.CheckGrantType(c.gt), "case %d", i)
	}
}

func TestFlow_CheckResponseType(t *testing.T) {
	f := New(NewConfig())
	cases := []struct {
		rt       types.ResponseType
		expected bool
	}{
		{types.ResponseTypeCode, true},
		{types.ResponseTypeToken, false},
		{types.NewResponseType(""), false},
	}
	for i, c := range cases {
		assert.Equalf(t, c.expected, f.CheckResponseType(c.rt), "case %d", i)
	}
}

func TestFlow_checkAuthEndpointHttpMethod(t *testing.T) {
	f := New(NewConfig())

	t.Run("success", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		assert.NoError(t, f.checkAuthEndpointHttpMethod(r))
	})

	t.Run("error_when_method_not_allowed", func(t *testing.T) {
		r := newAuthReq(http.MethodPost)
		err := f.checkAuthEndpointHttpMethod(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("success_with_custom_methods", func(t *testing.T) {
		f2 := New(NewConfig().SetAuthEndpointHttpMethods([]string{http.MethodPost, http.MethodGet}))
		r := newAuthReq(http.MethodPost)
		assert.NoError(t, f2.checkAuthEndpointHttpMethod(r))
	})
}

func TestFlow_checkTokenEndpointHttpMethod(t *testing.T) {
	f := New(NewConfig())

	t.Run("success", func(t *testing.T) {
		r := newTokenReq()
		assert.NoError(t, f.checkTokenEndpointHttpMethod(r))
	})

	t.Run("error_when_method_not_allowed", func(t *testing.T) {
		r := &requests.TokenRequest{Request: httptest.NewRequest(http.MethodGet, "/token", nil)}
		err := f.checkTokenEndpointHttpMethod(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}

func TestFlow_checkClient(t *testing.T) {
	mockClientMgr := authcodemock.NewMockClientManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr))

	t.Run("success", func(t *testing.T) {
		client := validClient()
		mockClientMgr.On("QueryByClientID", mock.Anything, "client-1").Return(client, nil).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "client-1"
		err := f.checkClient(r)
		assert.NoError(t, err)
		assert.Equal(t, client, r.Client)
	})

	t.Run("error_when_client_id_missing", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.ClientID = ""
		err := f.checkClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_store_returns_error", func(t *testing.T) {
		mockClientMgr.On("QueryByClientID", mock.Anything, "bad-client").Return(nil, errors.New("db error")).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "bad-client"
		err := f.checkClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
	})

	t.Run("error_when_client_not_found", func(t *testing.T) {
		mockClientMgr.On("QueryByClientID", mock.Anything, "unknown").Return(nil, nil).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "unknown"
		err := f.checkClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}

func TestFlow_validateRedirectURI(t *testing.T) {
	f := New(NewConfig())

	t.Run("success_with_registered_redirect_uri", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.RedirectURI = "https://example.com/cb"
		assert.NoError(t, f.validateRedirectURI(r))
	})

	t.Run("success_fallback_to_default_redirect_uri", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.RedirectURI = ""
		err := f.validateRedirectURI(r)
		assert.NoError(t, err)
		assert.Equal(t, "https://example.com/cb", r.RedirectURI)
	})

	t.Run("error_when_redirect_uri_missing_and_no_default", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = &sql.Client{}
		r.RedirectURI = ""
		err := f.validateRedirectURI(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_redirect_uri_not_registered", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.RedirectURI = "https://evil.com/cb"
		err := f.validateRedirectURI(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}

func TestFlow_validateResponseType(t *testing.T) {
	f := New(NewConfig())

	t.Run("success", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.ResponseType = types.ResponseTypeCode
		assert.NoError(t, f.validateResponseType(r))
	})

	t.Run("error_when_response_type_missing", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.ResponseType = types.NewResponseType("")
		err := f.validateResponseType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_response_type_is_not_code", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.ResponseType = types.ResponseTypeToken
		err := f.validateResponseType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported_response_type")
	})

	t.Run("error_when_client_does_not_allow_response_type", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.Client = &sql.Client{ResponseTypes: []string{}} // no code allowed
		r.ResponseType = types.ResponseTypeCode
		r.RedirectURI = "https://example.com/cb"
		err := f.validateResponseType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized_client")
	})
}

func TestFlow_validateScope(t *testing.T) {
	t.Run("policy_reject/error_when_scope_omitted", func(t *testing.T) {
		f := New(NewConfig().SetOmittedScopePolicy(OmittedScopePolicyReject))
		r := newAuthReq(http.MethodGet)
		r.Client = validClient()
		r.Scopes = types.Scopes{}
		err := f.validateScope(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
	})

	t.Run("policy_use_client_default/uses_client_scopes_when_omitted", func(t *testing.T) {
		f := New(NewConfig().SetOmittedScopePolicy(OmittedScopePolicyUseClientDefault))
		r := newAuthReq(http.MethodGet)
		r.Client = validClient() // allows: read, write
		r.Scopes = types.Scopes{}
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"read", "write"}, r.Scopes.String())
	})

	t.Run("success_filters_allowed_scopes", func(t *testing.T) {
		f := New(NewConfig())
		r := newAuthReq(http.MethodGet)
		r.Client = validClient() // allows: read, write
		r.Scopes = types.NewScopes([]string{"read", "write"})
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"read", "write"}, r.Scopes.String())
	})

	t.Run("success_filters_to_allowed_subset", func(t *testing.T) {
		f := New(NewConfig())
		r := newAuthReq(http.MethodGet)
		r.Client = validClient() // allows: read, write
		r.Scopes = types.NewScopes([]string{"read", "admin"})
		err := f.validateScope(r)
		assert.NoError(t, err)
		assert.Equal(t, []string{"read"}, r.Scopes.String())
	})

	t.Run("error_when_all_scopes_denied", func(t *testing.T) {
		f := New(NewConfig())
		r := newAuthReq(http.MethodGet)
		r.Client = validClient() // allows: read, write
		r.Scopes = types.NewScopes([]string{"admin", "superuser"})
		r.RedirectURI = "https://example.com/cb"
		err := f.validateScope(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_scope")
	})
}

func TestFlow_validateGrantType(t *testing.T) {
	f := New(NewConfig())

	t.Run("success", func(t *testing.T) {
		r := newTokenReq()
		r.GrantType = types.GrantTypeAuthorizationCode
		assert.NoError(t, f.validateGrantType(r))
	})

	t.Run("error_when_grant_type_missing", func(t *testing.T) {
		r := newTokenReq()
		r.GrantType = types.NewGrantType("")
		err := f.validateGrantType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_grant_type_not_authorization_code", func(t *testing.T) {
		r := newTokenReq()
		r.GrantType = types.GrantTypeROPC
		err := f.validateGrantType(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported_grant_type")
	})
}

func TestFlow_authenticateClient(t *testing.T) {
	mockClientMgr := authcodemock.NewMockClientManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr))

	t.Run("success", func(t *testing.T) {
		client := validClient()
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, EndpointToken).Return(client, nil).Once()

		r := newTokenReq()
		err := f.authenticateClient(r)
		assert.NoError(t, err)
		assert.Equal(t, client, r.Client)
	})

	t.Run("error_when_client_not_found", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, EndpointToken).Return(nil, nil).Once()

		r := newTokenReq()
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})

	t.Run("error_when_store_returns_error", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, EndpointToken).Return(nil, errors.New("db error")).Once()

		r := newTokenReq()
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
	})
}

func TestFlow_validateAuthCode(t *testing.T) {
	mockAuthCodeMgr := authcodemock.NewMockAuthCodeManager(t)
	f := New(NewConfig().SetAuthCodeManager(mockAuthCodeMgr))

	client := validClient()
	validCode := &sql.AuthorizationCode{
		Code:        "auth-code-123",
		ClientID:    client.ClientID,
		UserID:      "user-1",
		RedirectURI: "https://example.com/cb",
		AuthTime:    time.Now().UTC(),
		ExpiresIn:   time.Hour,
	}

	t.Run("success", func(t *testing.T) {
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "auth-code-123").Return(validCode, nil).Once()

		r := newTokenReq()
		r.Code = "auth-code-123"
		r.Client = client
		r.RedirectURI = "https://example.com/cb"
		err := f.validateAuthCode(r)
		assert.NoError(t, err)
		assert.Equal(t, validCode, r.AuthCode)
	})

	t.Run("error_when_code_missing", func(t *testing.T) {
		r := newTokenReq()
		r.Code = ""
		err := f.validateAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})

	t.Run("error_when_code_not_found", func(t *testing.T) {
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "unknown-code").Return(nil, nil).Once()

		r := newTokenReq()
		r.Code = "unknown-code"
		r.Client = client
		err := f.validateAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("error_when_code_belongs_to_different_client", func(t *testing.T) {
		otherClientCode := &sql.AuthorizationCode{
			Code:      "other-code",
			ClientID:  "other-client",
			AuthTime:  time.Now().UTC(),
			ExpiresIn: time.Hour,
		}
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "other-code").Return(otherClientCode, nil).Once()

		r := newTokenReq()
		r.Code = "other-code"
		r.Client = client // client-1 != other-client
		err := f.validateAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("error_when_code_is_expired", func(t *testing.T) {
		expiredCode := &sql.AuthorizationCode{
			Code:      "expired-code",
			ClientID:  client.ClientID,
			AuthTime:  time.Now().UTC().Add(-2 * time.Hour),
			ExpiresIn: time.Hour, // expired 1 hour ago
		}
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "expired-code").Return(expiredCode, nil).Once()

		r := newTokenReq()
		r.Code = "expired-code"
		r.Client = client
		err := f.validateAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("error_when_redirect_uri_mismatch", func(t *testing.T) {
		codeWithRedirect := &sql.AuthorizationCode{
			Code:        "code-with-uri",
			ClientID:    client.ClientID,
			RedirectURI: "https://example.com/cb",
			AuthTime:    time.Now().UTC(),
			ExpiresIn:   time.Hour,
		}
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "code-with-uri").Return(codeWithRedirect, nil).Once()

		r := newTokenReq()
		r.Code = "code-with-uri"
		r.Client = client
		r.RedirectURI = "https://other.com/cb" // mismatch
		err := f.validateAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("error_when_store_returns_error", func(t *testing.T) {
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "error-code").Return(nil, errors.New("db error")).Once()

		r := newTokenReq()
		r.Code = "error-code"
		r.Client = client
		err := f.validateAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
	})
}

func TestFlow_genAuthCode(t *testing.T) {
	mockAuthCodeMgr := authcodemock.NewMockAuthCodeManager(t)
	f := New(NewConfig().SetAuthCodeManager(mockAuthCodeMgr))

	t.Run("success", func(t *testing.T) {
		code := &sql.AuthorizationCode{}
		mockAuthCodeMgr.On("New").Return(code).Once()
		mockAuthCodeMgr.On("Generate", mock.Anything, mock.AnythingOfType("*sql.AuthorizationCode"), mock.Anything).Return(nil).Once()

		r := newAuthReq(http.MethodGet)
		got, err := f.genAuthCode(r)
		assert.NoError(t, err)
		assert.Equal(t, code, got)
	})

	t.Run("error_when_new_returns_nil", func(t *testing.T) {
		mockAuthCodeMgr.On("New").Return(nil).Once()

		r := newAuthReq(http.MethodGet)
		got, err := f.genAuthCode(r)
		assert.ErrorIs(t, err, ErrNilAuthCode)
		assert.Nil(t, got)
	})

	t.Run("error_when_generate_fails", func(t *testing.T) {
		code := &sql.AuthorizationCode{}
		mockAuthCodeMgr.On("New").Return(code).Once()
		mockAuthCodeMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("generate error")).Once()

		r := newAuthReq(http.MethodGet)
		got, err := f.genAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "generate error")
		assert.Nil(t, got)
	})
}

func TestFlow_genToken(t *testing.T) {
	mockTokenMgr := authcodemock.NewMockTokenManager(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr))

	clientWithRefresh := &sql.Client{
		ClientID:   "client-1",
		GrantTypes: []string{"authorization_code", "refresh_token"},
	}
	clientWithoutRefresh := &sql.Client{
		ClientID:   "client-2",
		GrantTypes: []string{"authorization_code"},
	}
	authCode := &sql.AuthorizationCode{
		Scopes: []string{"read"},
	}

	t.Run("success_with_refresh_token", func(t *testing.T) {
		token := &sql.Token{}
		mockTokenMgr.On("New").Return(token).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, true).Return(nil).Once()

		r := newTokenReq()
		r.Client = clientWithRefresh
		r.AuthCode = authCode
		got, err := f.genToken(r)
		assert.NoError(t, err)
		assert.Equal(t, token, got)
	})

	t.Run("success_without_refresh_token", func(t *testing.T) {
		token := &sql.Token{}
		mockTokenMgr.On("New").Return(token).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, false).Return(nil).Once()

		r := newTokenReq()
		r.Client = clientWithoutRefresh
		r.AuthCode = authCode
		got, err := f.genToken(r)
		assert.NoError(t, err)
		assert.Equal(t, token, got)
	})

	t.Run("error_when_new_returns_nil", func(t *testing.T) {
		mockTokenMgr.On("New").Return(nil).Once()

		r := newTokenReq()
		r.Client = clientWithRefresh
		r.AuthCode = authCode
		got, err := f.genToken(r)
		assert.ErrorIs(t, err, ErrNilToken)
		assert.Nil(t, got)
	})

	t.Run("error_when_generate_fails", func(t *testing.T) {
		token := &sql.Token{}
		mockTokenMgr.On("New").Return(token).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(errors.New("generate error")).Once()

		r := newTokenReq()
		r.Client = clientWithRefresh
		r.AuthCode = authCode
		got, err := f.genToken(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "generate error")
		assert.Nil(t, got)
	})
}

func TestFlow_queryUserByAuthCode(t *testing.T) {
	mockUserMgr := authcodemock.NewMockUserManager(t)
	f := New(NewConfig().SetUserManager(mockUserMgr))

	t.Run("success", func(t *testing.T) {
		user := &sql.User{UserID: "user-1"}
		mockUserMgr.On("QueryUserByCode", mock.Anything, mock.Anything, mock.Anything).Return(user, nil).Once()

		r := newTokenReq()
		r.AuthCode = &sql.AuthorizationCode{UserID: "user-1"}
		err := f.queryUserByAuthCode(r)
		assert.NoError(t, err)
		assert.Equal(t, user, r.User)
	})

	t.Run("error_when_user_id_empty", func(t *testing.T) {
		r := newTokenReq()
		r.AuthCode = &sql.AuthorizationCode{UserID: ""}
		err := f.queryUserByAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("error_when_user_not_found", func(t *testing.T) {
		mockUserMgr.On("QueryUserByCode", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Once()

		r := newTokenReq()
		r.AuthCode = &sql.AuthorizationCode{UserID: "user-1"}
		err := f.queryUserByAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("error_when_store_returns_error", func(t *testing.T) {
		mockUserMgr.On("QueryUserByCode", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("db error")).Once()

		r := newTokenReq()
		r.AuthCode = &sql.AuthorizationCode{UserID: "user-1"}
		err := f.queryUserByAuthCode(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
	})
}

func TestFlow_AuthorizationResponse(t *testing.T) {
	mockAuthCodeMgr := authcodemock.NewMockAuthCodeManager(t)
	f := New(NewConfig().SetAuthCodeManager(mockAuthCodeMgr))

	t.Run("success", func(t *testing.T) {
		code := &sql.AuthorizationCode{Code: "generated-code"}
		mockAuthCodeMgr.On("New").Return(code).Once()
		mockAuthCodeMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockAuthCodeMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		r := newAuthReq(http.MethodGet)
		r.RedirectURI = "https://example.com/cb"
		r.State = "xyz"
		r.User = &sql.User{UserID: "user-1"}
		rw := httptest.NewRecorder()

		err := f.AuthorizationResponse(r, rw)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rw.Code)

		location := rw.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/cb")
		assert.Contains(t, location, "code=generated-code")
		assert.Contains(t, location, "state=xyz")
	})

	t.Run("success_without_state", func(t *testing.T) {
		code := &sql.AuthorizationCode{Code: "generated-code"}
		mockAuthCodeMgr.On("New").Return(code).Once()
		mockAuthCodeMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockAuthCodeMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		r := newAuthReq(http.MethodGet)
		r.RedirectURI = "https://example.com/cb"
		r.State = ""
		r.User = &sql.User{UserID: "user-1"}
		rw := httptest.NewRecorder()

		err := f.AuthorizationResponse(r, rw)
		assert.NoError(t, err)
		location := rw.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})

	t.Run("error_when_user_is_nil", func(t *testing.T) {
		r := newAuthReq(http.MethodGet)
		r.RedirectURI = "https://example.com/cb"
		r.State = "xyz"
		r.User = nil
		rw := httptest.NewRecorder()

		err := f.AuthorizationResponse(r, rw)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
	})

	t.Run("error_when_save_fails", func(t *testing.T) {
		code := &sql.AuthorizationCode{Code: "generated-code"}
		mockAuthCodeMgr.On("New").Return(code).Once()
		mockAuthCodeMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockAuthCodeMgr.On("Save", mock.Anything, mock.Anything).Return(errors.New("save error")).Once()

		r := newAuthReq(http.MethodGet)
		r.RedirectURI = "https://example.com/cb"
		r.User = &sql.User{UserID: "user-1"}
		rw := httptest.NewRecorder()

		err := f.AuthorizationResponse(r, rw)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "save error")
	})
}

func TestFlow_TokenResponse(t *testing.T) {
	mockUserMgr := authcodemock.NewMockUserManager(t)
	mockAuthCodeMgr := authcodemock.NewMockAuthCodeManager(t)
	mockTokenMgr := authcodemock.NewMockTokenManager(t)

	f := New(NewConfig().
		SetUserManager(mockUserMgr).
		SetAuthCodeManager(mockAuthCodeMgr).
		SetTokenManager(mockTokenMgr))

	t.Run("success", func(t *testing.T) {
		user := &sql.User{UserID: "user-1"}
		token := &sql.Token{AccessToken: "tok-123"}

		mockUserMgr.On("QueryUserByCode", mock.Anything, mock.Anything, mock.Anything).Return(user, nil).Once()
		mockTokenMgr.On("New").Return(token).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()
		mockAuthCodeMgr.On("DeleteByCode", mock.Anything, "auth-code-123").Return(nil).Once()
		mockTokenMgr.On("Save", mock.Anything, mock.Anything).Return(nil).Once()

		r := newTokenReq()
		r.Client = validClient()
		r.AuthCode = &sql.AuthorizationCode{
			Code:   "auth-code-123",
			UserID: "user-1",
		}
		rw := httptest.NewRecorder()

		err := f.TokenResponse(r, rw)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("error_when_delete_fails_before_save", func(t *testing.T) {
		user := &sql.User{UserID: "user-1"}
		token := &sql.Token{}

		mockUserMgr.On("QueryUserByCode", mock.Anything, mock.Anything, mock.Anything).Return(user, nil).Once()
		mockTokenMgr.On("New").Return(token).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()
		// Delete fails → Save must NOT be called
		mockAuthCodeMgr.On("DeleteByCode", mock.Anything, "code-abc").Return(errors.New("db error")).Once()

		r := newTokenReq()
		r.Client = validClient()
		r.AuthCode = &sql.AuthorizationCode{
			Code:   "code-abc",
			UserID: "user-1",
		}
		rw := httptest.NewRecorder()

		err := f.TokenResponse(r, rw)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")
		// Save was not called — verified by mock expectations (no matching On for Save)
	})
}

func TestFlow_ValidateConsentRequest(t *testing.T) {
	mockClientMgr := authcodemock.NewMockClientManager(t)
	mockConsentValidator := authcodemock.NewMockConsentRequestValidator(t)

	cfg := NewConfig().
		SetClientManager(mockClientMgr).
		RegisterExtension(mockConsentValidator)
	f := New(cfg)

	client := validClient()

	t.Run("success_calls_consent_validator", func(t *testing.T) {
		mockClientMgr.On("QueryByClientID", mock.Anything, "client-1").Return(client, nil).Once()
		mockConsentValidator.On("ValidateConsentRequest", mock.Anything).Return(nil).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "client-1"
		r.RedirectURI = "https://example.com/cb"
		r.ResponseType = types.ResponseTypeCode
		r.Scopes = types.NewScopes([]string{"read"})

		err := f.ValidateConsentRequest(r)
		assert.NoError(t, err)
	})

	t.Run("error_when_consent_validator_returns_error", func(t *testing.T) {
		mockClientMgr.On("QueryByClientID", mock.Anything, "client-1").Return(client, nil).Once()
		mockConsentValidator.On("ValidateConsentRequest", mock.Anything).Return(errors.New("consent denied")).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "client-1"
		r.RedirectURI = "https://example.com/cb"
		r.ResponseType = types.ResponseTypeCode
		r.Scopes = types.NewScopes([]string{"read"})

		err := f.ValidateConsentRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "consent denied")
	})
}

func TestFlow_ValidateAuthorizationRequest_WithExtension(t *testing.T) {
	mockClientMgr := authcodemock.NewMockClientManager(t)
	mockAuthReqValidator := authcodemock.NewMockAuthorizationRequestValidator(t)

	cfg := NewConfig().
		SetClientManager(mockClientMgr).
		RegisterExtension(mockAuthReqValidator)
	f := New(cfg)

	client := validClient()

	t.Run("success_calls_extension", func(t *testing.T) {
		mockClientMgr.On("QueryByClientID", mock.Anything, "client-1").Return(client, nil).Once()
		mockAuthReqValidator.On("ValidateAuthorizationRequest", mock.Anything).Return(nil).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "client-1"
		r.RedirectURI = "https://example.com/cb"
		r.ResponseType = types.ResponseTypeCode
		r.Scopes = types.NewScopes([]string{"read"})

		err := f.ValidateAuthorizationRequest(r)
		assert.NoError(t, err)
		assert.Equal(t, types.GrantTypeAuthorizationCode, r.GrantType)
	})

	t.Run("error_when_extension_returns_error", func(t *testing.T) {
		mockClientMgr.On("QueryByClientID", mock.Anything, "client-1").Return(client, nil).Once()
		mockAuthReqValidator.On("ValidateAuthorizationRequest", mock.Anything).Return(errors.New("ext error")).Once()

		r := newAuthReq(http.MethodGet)
		r.ClientID = "client-1"
		r.RedirectURI = "https://example.com/cb"
		r.ResponseType = types.ResponseTypeCode
		r.Scopes = types.NewScopes([]string{"read"})

		err := f.ValidateAuthorizationRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ext error")
	})
}

func TestFlow_ValidateTokenRequest_WithExtension(t *testing.T) {
	mockClientMgr := authcodemock.NewMockClientManager(t)
	mockAuthCodeMgr := authcodemock.NewMockAuthCodeManager(t)
	mockTokenReqValidator := authcodemock.NewMockTokenRequestValidator(t)

	cfg := NewConfig().
		SetClientManager(mockClientMgr).
		SetAuthCodeManager(mockAuthCodeMgr).
		RegisterExtension(mockTokenReqValidator)
	f := New(cfg)

	client := validClient()
	authCode := &sql.AuthorizationCode{
		Code:      "code-xyz",
		ClientID:  "client-1",
		AuthTime:  time.Now().UTC(),
		ExpiresIn: time.Hour,
	}

	t.Run("success_calls_extension", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, EndpointToken).Return(client, nil).Once()
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "code-xyz").Return(authCode, nil).Once()
		mockTokenReqValidator.On("ValidateTokenRequest", mock.Anything).Return(nil).Once()

		r := newTokenReq()
		r.GrantType = types.GrantTypeAuthorizationCode
		r.Code = "code-xyz"

		err := f.ValidateTokenRequest(r)
		assert.NoError(t, err)
	})

	t.Run("error_when_extension_returns_error", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, EndpointToken).Return(client, nil).Once()
		mockAuthCodeMgr.On("QueryByCode", mock.Anything, "code-xyz").Return(authCode, nil).Once()
		mockTokenReqValidator.On("ValidateTokenRequest", mock.Anything).Return(errors.New("pkce error")).Once()

		r := newTokenReq()
		r.GrantType = types.GrantTypeAuthorizationCode
		r.Code = "code-xyz"

		err := f.ValidateTokenRequest(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pkce error")
	})
}
