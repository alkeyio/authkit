package authkit

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/types"
)

type stubAuthorizationGrant struct {
	responseType types.ResponseType
	validateErr  error
	responseErr  error
}

func (s *stubAuthorizationGrant) CheckResponseType(typ types.ResponseType) bool {
	return typ == s.responseType
}

func (s *stubAuthorizationGrant) ValidateAuthorizationRequest(_ *requests.AuthorizationRequest) error {
	return s.validateErr
}

func (s *stubAuthorizationGrant) AuthorizationResponse(_ *requests.AuthorizationRequest, _ http.ResponseWriter) error {
	return s.responseErr
}

type stubConsentGrant struct {
	responseType types.ResponseType
	validateErr  error
	responseErr  error
}

func (s *stubConsentGrant) CheckResponseType(typ types.ResponseType) bool {
	return typ == s.responseType
}

func (s *stubConsentGrant) ValidateConsentRequest(_ *requests.AuthorizationRequest) error {
	return s.validateErr
}

func (s *stubConsentGrant) AuthorizationResponse(_ *requests.AuthorizationRequest, _ http.ResponseWriter) error {
	return s.responseErr
}

type stubTokenGrant struct {
	grantType   types.GrantType
	validateErr error
	responseErr error
}

func (s *stubTokenGrant) CheckGrantType(gt types.GrantType) bool {
	return gt == s.grantType
}

func (s *stubTokenGrant) ValidateTokenRequest(_ *requests.TokenRequest) error {
	return s.validateErr
}

func (s *stubTokenGrant) TokenResponse(_ *requests.TokenRequest, _ http.ResponseWriter) error {
	return s.responseErr
}

type stubEndpoint struct {
	name        string
	responseErr error
}

func (s *stubEndpoint) CheckEndpoint(name string) bool {
	return name == s.name
}

func (s *stubEndpoint) EndpointResponse(_ *http.Request, _ http.ResponseWriter) error {
	return s.responseErr
}

// allGrant implements AuthorizationGrant, ConsentGrant, and TokenGrant simultaneously.
type allGrant struct{}

func (g *allGrant) CheckResponseType(_ types.ResponseType) bool                         { return false }
func (g *allGrant) ValidateAuthorizationRequest(_ *requests.AuthorizationRequest) error { return nil }
func (g *allGrant) ValidateConsentRequest(_ *requests.AuthorizationRequest) error       { return nil }
func (g *allGrant) AuthorizationResponse(_ *requests.AuthorizationRequest, _ http.ResponseWriter) error {
	return nil
}
func (g *allGrant) CheckGrantType(_ types.GrantType) bool                               { return false }
func (g *allGrant) ValidateTokenRequest(_ *requests.TokenRequest) error                 { return nil }
func (g *allGrant) TokenResponse(_ *requests.TokenRequest, _ http.ResponseWriter) error { return nil }

func newAuthorizeRequest(responseType string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "/authorize?response_type="+responseType, nil)
}

func newTokenFormRequest(grantType string) *http.Request {
	body := strings.NewReader("grant_type=" + grantType)
	hr := httptest.NewRequest(http.MethodPost, "/token", body)
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return hr
}

func TestNewServer(t *testing.T) {
	srv := NewServer()
	require.NotNil(t, srv)
	assert.Empty(t, srv.authorizationGrants)
	assert.Empty(t, srv.consentGrants)
	assert.Empty(t, srv.tokenGrants)
	assert.Empty(t, srv.endpoints)
	assert.Nil(t, srv.errHandler)
}

func TestServer_RegisterAuthorizationGrant(t *testing.T) {
	t.Run("registers_when_interface_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterAuthorizationGrant(&stubAuthorizationGrant{})
		assert.Len(t, srv.authorizationGrants, 1)
		assert.Empty(t, srv.consentGrants)
		assert.Empty(t, srv.tokenGrants)
	})

	t.Run("ignores_when_interface_not_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterAuthorizationGrant(struct{}{})
		assert.Empty(t, srv.authorizationGrants)
	})
}

func TestServer_RegisterConsentGrant(t *testing.T) {
	t.Run("registers_when_interface_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterConsentGrant(&stubConsentGrant{})
		assert.Len(t, srv.consentGrants, 1)
		assert.Empty(t, srv.authorizationGrants)
		assert.Empty(t, srv.tokenGrants)
	})

	t.Run("ignores_when_interface_not_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterConsentGrant(struct{}{})
		assert.Empty(t, srv.consentGrants)
	})
}

func TestServer_RegisterTokenGrant(t *testing.T) {
	t.Run("registers_when_interface_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterTokenGrant(&stubTokenGrant{})
		assert.Len(t, srv.tokenGrants, 1)
		assert.Empty(t, srv.authorizationGrants)
		assert.Empty(t, srv.consentGrants)
	})

	t.Run("ignores_when_interface_not_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterTokenGrant(struct{}{})
		assert.Empty(t, srv.tokenGrants)
	})
}

func TestServer_RegisterEndpoint(t *testing.T) {
	t.Run("registers_when_interface_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterEndpoint(&stubEndpoint{})
		assert.Len(t, srv.endpoints, 1)
	})

	t.Run("ignores_when_interface_not_satisfied", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterEndpoint(struct{}{})
		assert.Empty(t, srv.endpoints)
	})
}

func TestServer_RegisterGrant(t *testing.T) {
	t.Run("registers_to_all_matching_slices", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterGrant(&allGrant{})
		assert.Len(t, srv.authorizationGrants, 1)
		assert.Len(t, srv.consentGrants, 1)
		assert.Len(t, srv.tokenGrants, 1)
	})

	t.Run("registers_only_matching_slices", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterGrant(&stubTokenGrant{})
		assert.Empty(t, srv.authorizationGrants)
		assert.Empty(t, srv.consentGrants)
		assert.Len(t, srv.tokenGrants, 1)
	})
}

func TestServer_AuthorizationGrant(t *testing.T) {
	t.Run("returns_matching_grant", func(t *testing.T) {
		srv := NewServer()
		grant := &stubAuthorizationGrant{responseType: types.ResponseTypeCode}
		srv.RegisterAuthorizationGrant(grant)

		r := &requests.AuthorizationRequest{ResponseType: types.ResponseTypeCode}
		got, err := srv.AuthorizationGrant(r)
		require.NoError(t, err)
		assert.Equal(t, grant, got)
	})

	t.Run("returns_first_matching_grant", func(t *testing.T) {
		srv := NewServer()
		first := &stubAuthorizationGrant{responseType: types.ResponseTypeCode}
		second := &stubAuthorizationGrant{responseType: types.ResponseTypeCode}
		srv.RegisterAuthorizationGrant(first)
		srv.RegisterAuthorizationGrant(second)

		r := &requests.AuthorizationRequest{ResponseType: types.ResponseTypeCode}
		got, err := srv.AuthorizationGrant(r)
		require.NoError(t, err)
		assert.Equal(t, first, got)
	})

	t.Run("returns_error_when_no_match", func(t *testing.T) {
		srv := NewServer()
		r := &requests.AuthorizationRequest{ResponseType: types.ResponseTypeCode}
		got, err := srv.AuthorizationGrant(r)
		assert.Nil(t, got)
		var authErr *autherrors.AuthKitError
		require.ErrorAs(t, err, &authErr)
		assert.ErrorIs(t, authErr.Code, autherrors.ErrUnsupportedResponseType)
	})
}

func TestServer_ConsentGrant(t *testing.T) {
	t.Run("returns_matching_grant", func(t *testing.T) {
		srv := NewServer()
		grant := &stubConsentGrant{responseType: types.ResponseTypeCode}
		srv.RegisterConsentGrant(grant)

		r := &requests.AuthorizationRequest{ResponseType: types.ResponseTypeCode}
		got, err := srv.ConsentGrant(r)
		require.NoError(t, err)
		assert.Equal(t, grant, got)
	})

	t.Run("returns_error_when_no_match", func(t *testing.T) {
		srv := NewServer()
		r := &requests.AuthorizationRequest{ResponseType: types.ResponseTypeCode}
		got, err := srv.ConsentGrant(r)
		assert.Nil(t, got)
		var authErr *autherrors.AuthKitError
		require.ErrorAs(t, err, &authErr)
		assert.ErrorIs(t, authErr.Code, autherrors.ErrUnsupportedResponseType)
	})
}

func TestServer_TokenGrant(t *testing.T) {
	t.Run("returns_matching_grant", func(t *testing.T) {
		srv := NewServer()
		grant := &stubTokenGrant{grantType: types.GrantTypeAuthorizationCode}
		srv.RegisterTokenGrant(grant)

		r := &requests.TokenRequest{GrantType: types.GrantTypeAuthorizationCode}
		got, err := srv.TokenGrant(r)
		require.NoError(t, err)
		assert.Equal(t, grant, got)
	})

	t.Run("returns_error_when_no_match", func(t *testing.T) {
		srv := NewServer()
		r := &requests.TokenRequest{GrantType: types.GrantTypeAuthorizationCode}
		got, err := srv.TokenGrant(r)
		assert.Nil(t, got)
		var authErr *autherrors.AuthKitError
		require.ErrorAs(t, err, &authErr)
		assert.ErrorIs(t, authErr.Code, autherrors.ErrUnsupportedGrantType)
	})
}

func TestServer_Endpoint(t *testing.T) {
	t.Run("returns_matching_endpoint", func(t *testing.T) {
		srv := NewServer()
		ep := &stubEndpoint{name: "introspect"}
		srv.RegisterEndpoint(ep)

		got, err := srv.Endpoint("introspect")
		require.NoError(t, err)
		assert.Equal(t, ep, got)
	})

	t.Run("returns_error_when_not_found", func(t *testing.T) {
		srv := NewServer()
		_, err := srv.Endpoint("introspect")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "introspect")
	})
}

func TestServer_CreateAuthorizationResponse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterAuthorizationGrant(&stubAuthorizationGrant{responseType: types.ResponseTypeCode})

		rw := httptest.NewRecorder()
		err := srv.CreateAuthorizationResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("error_when_request_parse_fails", func(t *testing.T) {
		srv := NewServer()
		hr := httptest.NewRequest(http.MethodGet, "/authorize?max_age=invalid", nil)
		rw := httptest.NewRecorder()

		err := srv.CreateAuthorizationResponse(hr, rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("error_when_no_matching_grant", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		err := srv.CreateAuthorizationResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("error_when_validate_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterAuthorizationGrant(&stubAuthorizationGrant{
			responseType: types.ResponseTypeCode,
			validateErr:  autherrors.InvalidRequestError().WithDescription("missing param"),
		})

		rw := httptest.NewRecorder()
		err := srv.CreateAuthorizationResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("error_when_response_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterAuthorizationGrant(&stubAuthorizationGrant{
			responseType: types.ResponseTypeCode,
			responseErr:  autherrors.InternalServerError(),
		})

		rw := httptest.NewRecorder()
		err := srv.CreateAuthorizationResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	})
}

func TestServer_CreateConsentResponse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterConsentGrant(&stubConsentGrant{responseType: types.ResponseTypeCode})

		rw := httptest.NewRecorder()
		err := srv.CreateConsentResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("error_when_no_matching_grant", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		err := srv.CreateConsentResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("error_when_validate_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterConsentGrant(&stubConsentGrant{
			responseType: types.ResponseTypeCode,
			validateErr:  autherrors.AccessDeniedError(),
		})

		rw := httptest.NewRecorder()
		err := srv.CreateConsentResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, rw.Code)
	})

	t.Run("error_when_response_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterConsentGrant(&stubConsentGrant{
			responseType: types.ResponseTypeCode,
			responseErr:  autherrors.InternalServerError(),
		})

		rw := httptest.NewRecorder()
		err := srv.CreateConsentResponse(newAuthorizeRequest("code"), rw, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	})
}

func TestServer_ValidateTokenRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewServer()
		grant := &stubTokenGrant{grantType: types.GrantTypeAuthorizationCode}
		srv.RegisterTokenGrant(grant)

		g, r, err := srv.ValidateTokenRequest(newTokenFormRequest("authorization_code"))
		require.NoError(t, err)
		assert.Equal(t, grant, g)
		assert.NotNil(t, r)
	})

	t.Run("error_when_no_matching_grant", func(t *testing.T) {
		srv := NewServer()
		g, r, err := srv.ValidateTokenRequest(newTokenFormRequest("authorization_code"))
		assert.Nil(t, g)
		assert.Nil(t, r)
		var authErr *autherrors.AuthKitError
		require.ErrorAs(t, err, &authErr)
		assert.ErrorIs(t, authErr.Code, autherrors.ErrUnsupportedGrantType)
	})

	t.Run("error_when_validate_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterTokenGrant(&stubTokenGrant{
			grantType:   types.GrantTypeAuthorizationCode,
			validateErr: autherrors.InvalidClientError(),
		})

		g, r, err := srv.ValidateTokenRequest(newTokenFormRequest("authorization_code"))
		assert.Nil(t, g)
		assert.Nil(t, r)
		var authErr *autherrors.AuthKitError
		require.ErrorAs(t, err, &authErr)
		assert.ErrorIs(t, authErr.Code, autherrors.ErrInvalidClient)
	})
}

func TestServer_CreateTokenResponse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterTokenGrant(&stubTokenGrant{grantType: types.GrantTypeAuthorizationCode})

		rw := httptest.NewRecorder()
		err := srv.CreateTokenResponse(newTokenFormRequest("authorization_code"), rw)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("error_when_no_matching_grant", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		err := srv.CreateTokenResponse(newTokenFormRequest("authorization_code"), rw)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("error_when_validate_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterTokenGrant(&stubTokenGrant{
			grantType:   types.GrantTypeAuthorizationCode,
			validateErr: autherrors.InvalidClientError(),
		})

		rw := httptest.NewRecorder()
		err := srv.CreateTokenResponse(newTokenFormRequest("authorization_code"), rw)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rw.Code)
	})

	t.Run("error_when_response_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterTokenGrant(&stubTokenGrant{
			grantType:   types.GrantTypeAuthorizationCode,
			responseErr: autherrors.InternalServerError(),
		})

		rw := httptest.NewRecorder()
		err := srv.CreateTokenResponse(newTokenFormRequest("authorization_code"), rw)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	})
}

func TestServer_EndpointResponse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterEndpoint(&stubEndpoint{name: "introspect"})

		hr := httptest.NewRequest(http.MethodPost, "/introspect", nil)
		rw := httptest.NewRecorder()

		err := srv.EndpointResponse(hr, rw, "introspect")
		assert.NoError(t, err)
	})

	t.Run("error_when_endpoint_not_found", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		err := srv.EndpointResponse(httptest.NewRequest(http.MethodPost, "/introspect", nil), rw, "introspect")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	})

	t.Run("error_when_endpoint_fails", func(t *testing.T) {
		srv := NewServer()
		srv.RegisterEndpoint(&stubEndpoint{
			name:        "introspect",
			responseErr: autherrors.InvalidRequestError(),
		})

		hr := httptest.NewRequest(http.MethodPost, "/introspect", nil)
		rw := httptest.NewRecorder()

		err := srv.EndpointResponse(hr, rw, "introspect")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})
}

func TestServer_HandleError(t *testing.T) {
	t.Run("calls_custom_error_handler", func(t *testing.T) {
		srv := NewServer()
		called := false
		srv.RegisterErrorHandler(func(_ *http.Request, rw http.ResponseWriter, _ error) error {
			called = true
			rw.WriteHeader(http.StatusTeapot)
			return nil
		})

		hr := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()

		err := srv.HandleError(hr, rw, errors.New("any error"))
		assert.NoError(t, err)
		assert.True(t, called)
		assert.Equal(t, http.StatusTeapot, rw.Code)
	})

	t.Run("redirects_when_error_has_redirect_uri", func(t *testing.T) {
		srv := NewServer()
		authErr := autherrors.InvalidRequestError().
			WithRedirectURI("https://example.com/cb").
			WithState("abc")

		hr := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		rw := httptest.NewRecorder()

		err := srv.HandleError(hr, rw, authErr)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rw.Code)
		assert.Contains(t, rw.Header().Get("Location"), "https://example.com/cb")
		assert.Contains(t, rw.Header().Get("Location"), "invalid_request")
	})

	t.Run("writes_json_for_authkiterror_without_redirect", func(t *testing.T) {
		srv := NewServer()
		authErr := autherrors.InvalidClientError()

		hr := httptest.NewRequest(http.MethodPost, "/token", nil)
		rw := httptest.NewRecorder()

		err := srv.HandleError(hr, rw, authErr)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Contains(t, rw.Header().Get("Content-Type"), "application/json")

		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
		assert.Equal(t, "invalid_client", body["error"])
	})

	t.Run("wraps_plain_error_as_server_error", func(t *testing.T) {
		srv := NewServer()

		hr := httptest.NewRequest(http.MethodPost, "/token", nil)
		rw := httptest.NewRecorder()

		err := srv.HandleError(hr, rw, errors.New("db connection failed"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)

		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
		assert.Equal(t, "server_error", body["error"])
	})
}

func TestServer_JSONResponse(t *testing.T) {
	t.Run("writes_status_and_json_body", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		data := map[string]interface{}{"token_type": "Bearer", "expires_in": float64(3600)}
		err := srv.JSONResponse(rw, http.StatusOK, nil, data)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Contains(t, rw.Header().Get("Content-Type"), "application/json")

		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
		assert.Equal(t, "Bearer", body["token_type"])
		assert.Equal(t, float64(3600), body["expires_in"])
	})

	t.Run("merges_extra_headers", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		extraHeader := http.Header{}
		extraHeader.Add("WWW-Authenticate", `Bearer realm="example"`)
		extraHeader.Add("WWW-Authenticate", `Basic realm="example"`)

		err := srv.JSONResponse(rw, http.StatusUnauthorized, extraHeader, map[string]interface{}{})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Equal(t, []string{`Bearer realm="example"`, `Basic realm="example"`}, rw.Header()["Www-Authenticate"])
	})

	t.Run("sets_cache_control_headers", func(t *testing.T) {
		srv := NewServer()
		rw := httptest.NewRecorder()

		err := srv.JSONResponse(rw, http.StatusOK, nil, map[string]interface{}{})
		assert.NoError(t, err)
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
	})
}
