package requests

import (
	"net/http/httptest"
	"testing"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthorizationRequestFromHttp(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/?response_type=code&client_id=myclient&redirect_uri=https://example.com/cb&scope=openid+email&state=xyz&max_age=300", nil)
		req, err := NewAuthorizationRequestFromHttp(r)
		assert.NoError(t, err)
		assert.Equal(t, types.ResponseTypeCode, req.ResponseType)
		assert.Equal(t, "myclient", req.ClientID)
		assert.Equal(t, "https://example.com/cb", req.RedirectURI)
		assert.Contains(t, req.Scopes.String(), "openid")
		assert.Contains(t, req.Scopes.String(), "email")
		assert.Equal(t, "xyz", req.State)
		assert.Equal(t, types.NewMaxAge(300), req.MaxAge)
	})

	t.Run("invalid_max_age_ignored", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/?max_age=abc", nil)
		req, err := NewAuthorizationRequestFromHttp(r)
		assert.NoError(t, err)
		assert.NotNil(t, req)
	})
}

func TestAuthorizationRequest_CheckResponseType(t *testing.T) {
	req := &AuthorizationRequest{}
	err := req.CheckResponseType()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.ResponseType = types.ResponseTypeCode
	assert.NoError(t, req.CheckResponseType())

	// optional when false is passed
	empty := &AuthorizationRequest{}
	assert.NoError(t, empty.CheckResponseType(false))
}

func TestAuthorizationRequest_CheckClientID(t *testing.T) {
	req := &AuthorizationRequest{}
	err := req.CheckClientID()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	assert.NoError(t, req.CheckClientID(false))

	req.ClientID = "myclient"
	assert.NoError(t, req.CheckClientID())
}

func TestAuthorizationRequest_CheckNonce(t *testing.T) {
	req := &AuthorizationRequest{}

	// required by default
	err := req.CheckNonce()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	// optional when false is passed
	assert.NoError(t, req.CheckNonce(false))

	req.Nonce = "mynonce"
	assert.NoError(t, req.CheckNonce())
}
