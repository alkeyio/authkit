package clientauth

// BaseHandler holds the ClientStore shared by all authentication handlers.
// Embed this struct in concrete handler types to avoid duplicating store management.
type BaseHandler struct {
	store ClientStore
}

// SetClientStore sets the client store without validation. Prefer MustClientStore
// when building handlers in production code.
func (h *BaseHandler) SetClientStore(store ClientStore) {
	h.store = store
}

// MustClientStore sets the client store and returns ErrNilClientStore if store is nil.
func (h *BaseHandler) MustClientStore(store ClientStore) error {
	if store == nil {
		return ErrNilClientStore
	}

	h.SetClientStore(store)
	return nil
}
