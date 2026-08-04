package clientauth

import (
	"net/http"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
	"github.com/tniah/authkit/utils"
)

// NoneAuthHandler implements the "none" authentication method for public clients
// (RFC 6749 §2.1). Public clients cannot keep a secret, so only client_id is
// required — no secret is transmitted or verified.
type NoneAuthHandler struct {
	*BaseHandler
}

// NewNoneAuthHandler creates a NoneAuthHandler with the given store.
func NewNoneAuthHandler(store ClientStore) *NoneAuthHandler {
	h := &NoneAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	h.SetClientStore(store)
	return h
}

// MustNoneAuthHandler creates a NoneAuthHandler and returns an error if store is nil.
func MustNoneAuthHandler(store ClientStore) (*NoneAuthHandler, error) {
	h := &NoneAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}
	return h, nil
}

// Method returns none.
func (h *NoneAuthHandler) Method() types.ClientAuthMethod {
	return types.ClientNoneAuthentication
}

// Authenticate extracts client_id from the POST form body and looks up the client.
// No secret verification is performed. Returns ErrInvalidClient if the request
// method is not POST, content type is wrong, client_id is missing, or the client
// is not found.
func (h *NoneAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
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

	return client, nil
}
