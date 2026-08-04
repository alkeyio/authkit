package rfc7662

import (
	"net/http"

	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
	"github.com/tniah/authkit/utils"
)

// Request holds the parsed parameters of an RFC 7662 introspection request.
type Request struct {
	Token         string
	TokenTypeHint types.TokenTypeHint

	Client  models.Client
	Tok     models.Token
	Request *http.Request
}

// NewRequestFromHTTP parses an introspection request from an HTTP request,
// extracting the token and optional token_type_hint form values.
func NewRequestFromHTTP(r *http.Request) *Request {
	return &Request{
		Token:         r.FormValue("token"),
		TokenTypeHint: types.NewTokenTypeHint(r.FormValue("token_type_hint")),
		Request:       r,
	}
}

// ValidateHTTPMethod returns an error if the request method is not POST,
// as required by RFC 7662 §2.1.
func (r *Request) ValidateHTTPMethod() error {
	if r.Request.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription("request must be \"POST\"")
	}

	return nil
}

// ValidateContentType returns an error if the Content-Type is not
// application/x-www-form-urlencoded, as required by RFC 7662 §2.1.
func (r *Request) ValidateContentType() error {
	ct, err := utils.ContentType(r.Request)
	if err != nil {
		return autherrors.InvalidRequestError()
	}

	if valid := ct.IsXWWWFormUrlencoded(); !valid {
		return autherrors.InvalidRequestError().WithDescription("content type must be \"application/x-www-form-urlencoded\"")
	}

	return nil
}

// ValidateToken returns an error if the token parameter is missing or empty.
func (r *Request) ValidateToken() error {
	if r.Token == "" {
		return autherrors.InvalidRequestError().WithDescription("\"token\" is empty or missing")
	}

	return nil
}
