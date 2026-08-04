package clientauth

import "errors"

var (
	// ErrInvalidClient is returned whenever client authentication fails —
	// client not found, wrong secret, unsupported auth method, etc.
	// A generic message is intentional to avoid leaking which check failed.
	ErrInvalidClient = errors.New("invalid client")

	// ErrNilClientStore is returned by MustClientStore when a nil store is provided.
	ErrNilClientStore = errors.New("client store is nil")
)
