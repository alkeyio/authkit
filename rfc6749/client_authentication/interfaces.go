package clientauth

import (
	"context"
	"net/http"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
)

// ClientStore is the data access layer for client lookup. Implement this
// interface to integrate with your storage backend (SQL, NoSQL, in-memory, etc.).
type ClientStore interface {
	// QueryByClientID retrieves the client with the given client_id.
	// Return (nil, nil) when the client does not exist.
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
}

// Handler authenticates a client for a specific authentication method.
// Register concrete handlers with Manager.Register to enable the corresponding
// client_secret_basic, client_secret_post, or none method.
type Handler interface {
	// Method returns the authentication method this handler is responsible for.
	Method() types.ClientAuthMethod
	// Authenticate extracts and validates client credentials from the request.
	// Return ErrInvalidClient on any authentication failure.
	Authenticate(r *http.Request) (models.Client, error)
}
