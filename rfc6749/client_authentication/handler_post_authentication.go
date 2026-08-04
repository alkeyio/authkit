package clientauth

import (
	"net/http"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
	"github.com/tniah/authkit/utils"
)

// PostAuthHandler implements client_secret_post authentication (RFC 6749 §2.3.1).
// The client authenticates by including client_id and client_secret as POST body
// parameters with Content-Type: application/x-www-form-urlencoded.
type PostAuthHandler struct {
	*BaseHandler
}

// NewPostAuthHandler creates a PostAuthHandler with the given store.
func NewPostAuthHandler(store ClientStore) *PostAuthHandler {
	h := &PostAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	h.SetClientStore(store)
	return h
}

// MustPostAuthHandler creates a PostAuthHandler and returns an error if store is nil.
func MustPostAuthHandler(store ClientStore) (*PostAuthHandler, error) {
	h := &PostAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}

	return h, nil
}

// Method returns client_secret_post.
func (h *PostAuthHandler) Method() types.ClientAuthMethod {
	return types.ClientPostAuthentication
}

// Authenticate extracts client_id and client_secret from the POST form body and
// validates them. Returns ErrInvalidClient if the request method is not POST,
// the content type is not application/x-www-form-urlencoded, the client is not
// found, or the secret does not match.
func (h *PostAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	if r.Method != http.MethodPost {
		return nil, ErrInvalidClient
	}

	ct, err := utils.ContentType(r)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if valid := ct.IsXWWWFormUrlencoded(); !valid {
		return nil, ErrInvalidClient
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.QueryByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if utils.IsNil(client) {
		return nil, ErrInvalidClient
	}

	clientSecret := r.PostFormValue("client_secret")
	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}
