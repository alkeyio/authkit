package errors

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewOAuth2Error(t *testing.T) {
	e := NewOAuth2Error(ErrInvalidRequest)
	assert.Equal(t, ErrInvalidRequest, e.Code)
	assert.Equal(t, http.StatusBadRequest, e.HttpCode)
	assert.Equal(t, Descriptions[ErrInvalidRequest], e.Description)
	assert.Empty(t, e.URI)

	// explicit description and URI
	e2 := NewOAuth2Error(ErrInvalidClient, "bad credentials", "https://example.com/docs")
	assert.Equal(t, "bad credentials", e2.Description)
	assert.Equal(t, "https://example.com/docs", e2.URI)

	// unknown code defaults to 400
	unknown := NewOAuth2Error(ErrMissingIssuer)
	assert.Equal(t, http.StatusBadRequest, unknown.HttpCode)
}

func TestOAuth2Error_Error(t *testing.T) {
	e := NewOAuth2Error(ErrInvalidRequest)
	assert.Contains(t, e.Error(), "invalid_request")
}

func TestOAuth2Error_Data(t *testing.T) {
	e := NewOAuth2Error(ErrInvalidRequest)
	data := e.Data()
	assert.Equal(t, "invalid_request", data[ErrCode])
	assert.NotEmpty(t, data[ErrDescription])
	assert.NotContains(t, data, ErrURI)

	e.URI = "https://example.com/docs"
	data = e.Data()
	assert.Equal(t, "https://example.com/docs", data[ErrURI])
}

func TestOAuth2Error_SetHttpCode(t *testing.T) {
	e := NewOAuth2Error(ErrInvalidRequest)
	e.SetHttpCode(http.StatusTeapot)
	assert.Equal(t, http.StatusTeapot, e.HttpCode)
}

func TestOAuth2Error_SetHeader(t *testing.T) {
	e := NewOAuth2Error(ErrInvalidClient)
	e.SetHeader("WWW-Authenticate", `Basic realm="example"`)
	assert.Equal(t, `Basic realm="example"`, e.HttpHeader.Get("WWW-Authenticate"))
}

func TestOAuth2Error_Response(t *testing.T) {
	e := NewOAuth2Error(ErrInvalidRequest)
	status, _, data := e.Response()
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", data[ErrCode])
}

func TestNewAuthKitError(t *testing.T) {
	e := NewAuthKitError(ErrInvalidRequest)
	assert.Equal(t, ErrInvalidRequest, e.Code)
	assert.Equal(t, http.StatusBadRequest, e.HttpCode)
}

func TestAuthKitError_With(t *testing.T) {
	e := NewAuthKitError(ErrInvalidRequest).
		WithDescription("custom desc").
		WithState("xyz").
		WithRedirectURI("https://example.com/cb").
		WithErrorURI("https://example.com/docs").
		WithCause(ErrInvalidRequest)

	assert.Equal(t, "custom desc", e.Description)
	assert.Equal(t, "xyz", e.State)
	assert.Equal(t, "https://example.com/cb", e.RedirectURI)
	assert.Equal(t, "https://example.com/docs", e.URI)
	assert.Equal(t, ErrInvalidRequest, e.Cause)
}

func TestAuthKitError_Data(t *testing.T) {
	e := NewAuthKitError(ErrInvalidRequest).WithState("abc")
	data := e.Data()
	assert.Equal(t, "abc", data[ErrState])

	// no state → state key absent
	e2 := NewAuthKitError(ErrInvalidRequest)
	data2 := e2.Data()
	assert.NotContains(t, data2, ErrState)
}

func TestAuthKitError_Response_InvalidClient(t *testing.T) {
	e := InvalidClientError()
	status, header, _ := e.Response()
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.NotEmpty(t, header.Get("WWW-Authenticate"))
}

func TestToAuthKitError(t *testing.T) {
	// already an *AuthKitError
	original := InvalidRequestError().WithDescription("test")
	result := ToAuthKitError(original)
	assert.Equal(t, original, result)

	// plain error → wrapped as InternalServerError
	result2 := ToAuthKitError(ErrInvalidRequest)
	assert.Equal(t, ErrServerError, result2.Code)
	assert.Equal(t, ErrInvalidRequest, result2.Cause)
}

func TestErrorConstructors(t *testing.T) {
	cases := []struct {
		fn       func() *AuthKitError
		code     error
		httpCode int
	}{
		{InvalidRequestError, ErrInvalidRequest, http.StatusBadRequest},
		{InvalidScopeError, ErrInvalidScope, http.StatusBadRequest},
		{InvalidClientError, ErrInvalidClient, http.StatusUnauthorized},
		{UnauthorizedClientError, ErrUnauthorizedClient, http.StatusBadRequest},
		{InvalidGrantError, ErrInvalidGrant, http.StatusBadRequest},
		{UnsupportedGrantTypeError, ErrUnsupportedGrantType, http.StatusBadRequest},
		{UnsupportedResponseTypeError, ErrUnsupportedResponseType, http.StatusBadRequest},
		{AccessDeniedError, ErrAccessDenied, http.StatusForbidden},
		{UnsupportedTokenType, ErrUnsupportedTokenType, http.StatusForbidden},
		{InternalServerError, ErrServerError, http.StatusInternalServerError},
		{LoginRequiredError, ErrLoginRequired, http.StatusUnauthorized},
		{ConsentRequiredError, ErrConsentRequired, http.StatusForbidden},
		{AccountSelectionRequiredError, ErrAccountSelectionRequired, http.StatusForbidden},
	}

	for _, c := range cases {
		e := c.fn()
		assert.Equal(t, c.code, e.Code, "code mismatch for %v", c.code)
		assert.Equal(t, c.httpCode, e.HttpCode, "httpCode mismatch for %v", c.code)
	}
}
