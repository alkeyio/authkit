package rfc7662

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/integrations/sql"
	"github.com/alkeyio/authkit/mocks/rfc7662"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestTokenIntrospectionFlow_EndpointResponse(t *testing.T) {
	cfg := NewConfig()
	h := NewTokenIntrospectionFlow(cfg)

	mockClient := &sql.Client{
		ClientID: uuid.NewString(),
	}
	mockToken := &sql.Token{
		TokenType:            "Bearer",
		AccessToken:          uuid.NewString(),
		RefreshToken:         uuid.NewString(),
		ClientID:             mockClient.ClientID,
		IssuedAt:             time.Now().UTC().Round(time.Second),
		AccessTokenExpiresIn: time.Hour * 24,
	}
	expected := map[string]interface{}{
		"client_id": mockClient.ClientID,
	}

	mockTokenMgr := rfc7662.NewMockTokenManager(t)
	mockTokenMgr.On("QueryByToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("types.TokenTypeHint")).Return(mockToken, nil).Once()
	mockTokenMgr.On("Inspect", mock.Anything, mock.Anything, mock.Anything).Return(expected).Once()
	cfg.SetTokenManager(mockTokenMgr)

	mockClientMgr := rfc7662.NewMockClientManager(t)
	mockClientMgr.On("Authenticate", mock.Anything, mock.AnythingOfType("*http.Request"), mock.AnythingOfType("map[types.ClientAuthMethod]bool"), mock.AnythingOfType("string")).Return(mockClient, nil).Once()
	mockClientMgr.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("*http.Request")).Return(true).Once()
	cfg.SetClientManager(mockClientMgr)

	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err := h.EndpointResponse(r, rw)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rw.Code)

	mockTokenMgr.AssertExpectations(t)
	mockClientMgr.AssertExpectations(t)
}

func TestTokenIntrospectionFlow_CheckEndpoint(t *testing.T) {
	cfg := NewConfig().SetEndpointName(EndpointNameTokenIntrospection)
	h := NewTokenIntrospectionFlow(cfg)
	cases := []struct {
		name     string
		expected bool
	}{
		{
			"my-endpoint",
			false,
		},
		{
			EndpointNameTokenIntrospection,
			true,
		},
	}
	for i, test := range cases {
		ret := h.CheckEndpoint(test.name)
		assert.Equalf(t, test.expected, ret, "case %d failed", i)
	}
}

func TestTokenIntrospectionFlow_authenticateToken(t *testing.T) {
	cfg := NewConfig()
	h := NewTokenIntrospectionFlow(cfg)

	mockClient := &sql.Client{}
	mockToken := &sql.Token{}
	mockTokenMgr := rfc7662.NewMockTokenManager(t)
	cfg.SetTokenManager(mockTokenMgr)

	mockClientMgr := rfc7662.NewMockClientManager(t)
	cfg.SetClientManager(mockClientMgr)

	t.Run("success", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewRequestFromHTTP(hr)

		mockTokenMgr.On("QueryByToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("types.TokenTypeHint")).Return(mockToken, nil).Once()
		mockClientMgr.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("*http.Request")).Return(true).Once()

		r.Client = mockClient
		err := h.authenticateToken(r)
		assert.NoError(t, err)

		mockTokenMgr.AssertExpectations(t)
		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_client_have_no_permission", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewRequestFromHTTP(hr)

		mockTokenMgr.On("QueryByToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("types.TokenTypeHint")).Return(mockToken, nil).Once()
		mockClientMgr.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("*http.Request")).Return(false).Once()
		r.Client = mockClient

		err := h.authenticateToken(r)
		authErr := autherrors.ToAuthKitError(err)
		assert.Equal(t, "client does not have permission to inspect token", authErr.Description)

		mockTokenMgr.AssertExpectations(t)
		mockClientMgr.AssertExpectations(t)
	})
}

func TestTokenIntrospectionFlow_checkParams(t *testing.T) {
	h := NewTokenIntrospectionFlow(NewConfig())

	t.Run("success", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewRequestFromHTTP(hr)
		err := h.checkParams(r)
		assert.NoError(t, err)
	})

	t.Run("error_when_http_method_is_disallowed", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodGet, "/", nil)
		r := NewRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr := autherrors.ToAuthKitError(err)
		assert.Equal(t, "request must be \"POST\"", authErr.Description)
	})

	t.Run("error_when_content_type_is_invalid", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		r := NewRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr := autherrors.ToAuthKitError(err)
		assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)
	})

	t.Run("error_when_media_type_is_not_supported", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{\"token\":\"my-token\"}"))
		hr.Header.Set("Content-Type", "application/json")
		r := NewRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr := autherrors.ToAuthKitError(err)
		assert.Equal(t, "content type must be \"application/x-www-form-urlencoded\"", authErr.Description)
	})

	t.Run("unknown_token_hint_is_ignored", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=my-hint"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewRequestFromHTTP(hr)
		err := h.checkParams(r)
		assert.NoError(t, err)
	})
}

func TestTokenIntrospectionFlow_introspectionPayload(t *testing.T) {
	mockTokenMgr := rfc7662.NewMockTokenManager(t)
	cfg := NewConfig().SetTokenManager(mockTokenMgr)
	h := NewTokenIntrospectionFlow(cfg)
	mockClient := &sql.Client{
		ClientID: uuid.NewString(),
	}

	t.Run("success", func(t *testing.T) {
		expected := map[string]interface{}{
			"active":   true,
			"iss":      "https://server.example.com/",
			"scope":    "read write dolphin",
			"username": "makai",
		}

		mockToken := &sql.Token{
			ClientID:             mockClient.ClientID,
			IssuedAt:             time.Now().UTC().Round(time.Second),
			AccessTokenExpiresIn: time.Hour * 24,
		}
		mockTokenMgr.On("Inspect", mock.Anything, mock.Anything, mock.Anything).Return(expected).Once()

		r := &Request{}
		r.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		r.Tok = mockToken
		r.Client = mockClient

		payload := h.introspectionPayload(r)
		assert.Equal(t, expected, payload)

		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_token_is_invalid", func(t *testing.T) {
		r := &Request{}
		r.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		r.Client = mockClient

		payload := h.introspectionPayload(r)
		assert.Equal(t, false, payload["active"])

		mockToken := &sql.Token{
			ClientID:             mockClient.ClientID,
			IssuedAt:             time.Now().UTC().Round(time.Second),
			AccessTokenExpiresIn: time.Hour * -24,
		}
		r.Tok = mockToken
		payload = h.introspectionPayload(r)
		assert.Equal(t, false, payload["active"])
	})
}
