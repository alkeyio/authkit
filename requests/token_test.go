package requests

import (
	"net/http/httptest"
	"strings"
	"testing"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenRequestFromHttp(t *testing.T) {
	body := strings.NewReader("grant_type=authorization_code&code=mycode&redirect_uri=https://example.com/cb&client_id=myclient&scope=openid+email&username=alice&password=secret&code_verifier=myverifier")
	r := httptest.NewRequest("POST", "/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req := NewTokenRequestFromHttp(r)
	assert.Equal(t, types.GrantTypeAuthorizationCode, req.GrantType)
	assert.Equal(t, "mycode", req.Code)
	assert.Equal(t, "https://example.com/cb", req.RedirectURI)
	assert.Equal(t, "myclient", req.ClientID)
	assert.Contains(t, req.Scopes.String(), "openid")
	assert.Contains(t, req.Scopes.String(), "email")
	assert.Equal(t, "alice", req.Username)
	assert.Equal(t, "secret", req.Password)
	assert.Equal(t, "myverifier", req.CodeVerifier)
	assert.Equal(t, r, req.Request)
}

func TestTokenRequest_CheckGrantType(t *testing.T) {
	req := &TokenRequest{}
	err := req.CheckGrantType()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.GrantType = types.GrantTypeAuthorizationCode
	assert.NoError(t, req.CheckGrantType())
}

func TestTokenRequest_CheckCode(t *testing.T) {
	req := &TokenRequest{}

	// required by default
	err := req.CheckCode()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	// optional when false is passed
	assert.NoError(t, req.CheckCode(false))

	req.Code = "mycode"
	assert.NoError(t, req.CheckCode())
}

func TestTokenRequest_CheckUsername(t *testing.T) {
	req := &TokenRequest{}
	err := req.CheckUsername()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.Username = "alice"
	assert.NoError(t, req.CheckUsername())
}

func TestTokenRequest_CheckPassword(t *testing.T) {
	req := &TokenRequest{}
	err := req.CheckPassword()
	authErr := autherrors.ToAuthKitError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.Password = "secret"
	assert.NoError(t, req.CheckPassword())
}
