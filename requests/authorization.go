package requests

import (
	"net/http"
	"strconv"
	"strings"

	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
)

// AuthorizationRequest holds the parsed parameters of an OAuth 2.0
// authorization endpoint request (RFC 6749 §3.1) including OIDC extensions.
// It is populated by NewAuthorizationRequestFromHttp and then enriched by
// the grant flow (Client, User fields).
type AuthorizationRequest struct {
	GrantType    types.GrantType
	ResponseType types.ResponseType
	ClientID     string
	RedirectURI  string
	Scopes       types.Scopes
	State        string

	Nonce        string
	ResponseMode types.ResponseMode
	Display      types.Display
	Prompts      types.Prompts
	MaxAge       types.MaxAge
	UILocales    types.Locales
	IDTokenHint  string
	LoginHint    string
	ACRValues    types.SpaceDelimitedArray

	CodeChallenge       string
	CodeChallengeMethod types.CodeChallengeMethod

	Client models.Client
	User   models.User

	Request *http.Request
}

// NewAuthorizationRequestFromHttp parses an OAuth 2.0 / OIDC authorization
// request from r. Parameters are read from the URL query string (or form
// body after r.ParseForm). Invalid or missing parameters are not validated
// here — that is left to the grant flow. The only exception is max_age: if
// present but not a valid non-negative integer, it is silently ignored and
// defaults to 0.
func NewAuthorizationRequestFromHttp(r *http.Request) (*AuthorizationRequest, error) {
	authReq := &AuthorizationRequest{
		ResponseType:        types.NewResponseType(r.FormValue("response_type")),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scopes:              types.NewScopes(strings.Fields(r.FormValue("scope"))),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		ResponseMode:        types.NewResponseMode(r.FormValue("response_mode")),
		Display:             types.NewDisplay(r.FormValue("display")),
		Prompts:             types.NewPrompts(strings.Fields(r.FormValue("prompt"))),
		UILocales:           types.NewLocales(strings.Fields(r.FormValue("ui_locales"))),
		IDTokenHint:         r.FormValue("id_token_hint"),
		LoginHint:           r.FormValue("login_hint"),
		ACRValues:           strings.Fields(r.FormValue("acr_values")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: types.NewCodeChallengeMethod(r.FormValue("code_challenge_method")),
		Request:             r,
	}

	maxAge := types.NewMaxAge(0)
	if v := r.FormValue("max_age"); v != "" {
		if ma, err := strconv.ParseUint(v, 10, 64); err == nil {
			maxAge = types.NewMaxAge(uint(ma))
		}
	}
	authReq.MaxAge = maxAge

	return authReq, nil
}

// CheckResponseType returns an error if response_type is missing. Required
// by default; pass false to treat it as optional.
func (r *AuthorizationRequest) CheckResponseType(required ...bool) error {
	if isRequired(true, required...) && r.ResponseType.IsEmpty() {
		return autherrors.InvalidRequestError().WithDescription("missing \"response_type\" in request").WithState(r.State)
	}

	return nil
}

// CheckClientID returns an error if client_id is missing. Required by
// default; pass false to treat it as optional.
func (r *AuthorizationRequest) CheckClientID(required ...bool) error {
	if isRequired(true, required...) && r.ClientID == "" {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"client_id\" in request").
			WithState(r.State)
	}

	return nil
}

// CheckNonce returns an error if nonce is missing. Required by default;
// pass false to treat it as optional.
func (r *AuthorizationRequest) CheckNonce(required ...bool) error {
	if isRequired(true, required...) && r.Nonce == "" {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"nonce\" in request").
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

// Method returns the HTTP method of the underlying request.
func (r *AuthorizationRequest) Method() string {
	return r.Request.Method
}
