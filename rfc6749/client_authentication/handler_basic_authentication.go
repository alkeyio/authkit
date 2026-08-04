package clientauth

import (
	"net/http"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
	"github.com/tniah/authkit/utils"
)

// BasicAuthHandler implements client_secret_basic authentication (RFC 6749 §2.3.1).
// The client authenticates by sending its client_id and client_secret as an
// HTTP Basic Authorization header: Authorization: Basic <base64(id:secret)>.
type BasicAuthHandler struct {
	*BaseHandler
}

// NewBasicAuthHandler creates a BasicAuthHandler with the given store.
func NewBasicAuthHandler(store ClientStore) *BasicAuthHandler {
	h := &BasicAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	h.SetClientStore(store)
	return h
}

// MustBasicAuthHandler creates a BasicAuthHandler and returns an error if store is nil.
func MustBasicAuthHandler(store ClientStore) (*BasicAuthHandler, error) {
	h := &BasicAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}

	return h, nil
}

// Method returns client_secret_basic.
func (h *BasicAuthHandler) Method() types.ClientAuthMethod {
	return types.ClientBasicAuthentication
}

// Authenticate extracts credentials from the Authorization header and validates
// them against the stored client. Returns ErrInvalidClient if the header is
// absent, the client is not found, or the secret does not match.
func (h *BasicAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.QueryByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if utils.IsNil(client) {
		return nil, ErrInvalidClient
	}

	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}
