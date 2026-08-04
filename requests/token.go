package requests

import (
	"net/http"
	"strings"

	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
)

// TokenRequest holds the parsed parameters of an OAuth 2.0 token endpoint
// request (RFC 6749 §3.2). It is populated by NewTokenRequestFromHttp and
// then enriched by the grant flow (Client, User, AuthCode fields).
type TokenRequest struct {
	GrantType   types.GrantType
	Code        string
	RedirectURI string
	ClientID    string
	Scopes      types.Scopes

	Username string
	Password string

	ClientAuthMethod types.ClientAuthMethod
	CodeVerifier     string

	Client   models.Client
	User     models.User
	AuthCode models.AuthorizationCode

	Request *http.Request
}

// NewTokenRequestFromHttp parses a token request from an HTTP request body,
// reading all standard OAuth 2.0 token endpoint parameters from the POST form values.
func NewTokenRequestFromHttp(r *http.Request) *TokenRequest {
	return &TokenRequest{
		GrantType:    types.NewGrantType(r.PostFormValue("grant_type")),
		Code:         r.PostFormValue("code"),
		RedirectURI:  r.PostFormValue("redirect_uri"),
		ClientID:     r.PostFormValue("client_id"),
		Scopes:       types.NewScopes(strings.Fields(r.PostFormValue("scope"))),
		Username:     r.PostFormValue("username"),
		Password:     r.PostFormValue("password"),
		CodeVerifier: r.PostFormValue("code_verifier"),
		Request:      r,
	}
}

// CheckGrantType returns an error if grant_type is missing or empty.
func (r *TokenRequest) CheckGrantType() error {
	if r.GrantType.IsEmpty() {
		return autherrors.InvalidRequestError().WithDescription("missing \"grant_type\" in request")
	}

	return nil
}

// CheckCode returns an error if code is missing. Required by default;
// pass false to treat it as optional.
func (r *TokenRequest) CheckCode(required ...bool) error {
	if isRequired(true, required...) && r.Code == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code\" in request")
	}

	return nil
}

// CheckUsername returns an error if username is missing or empty.
func (r *TokenRequest) CheckUsername() error {
	if r.Username == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"username\" in request")
	}

	return nil
}

// CheckPassword returns an error if password is missing or empty.
func (r *TokenRequest) CheckPassword() error {
	if r.Password == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"password\" in request")
	}

	return nil
}

// Method returns the HTTP method of the underlying request.
func (r *TokenRequest) Method() string {
	return r.Request.Method
}
