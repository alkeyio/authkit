package manager

import (
	"context"
	"net/http"
	"sync"

	"github.com/alkeyio/authkit/integrations/sql"
	authkitmodels "github.com/alkeyio/authkit/models"
	clientauth "github.com/alkeyio/authkit/rfc6749/client_authentication"
	authkittypes "github.com/alkeyio/authkit/types"
)

// ClientManager is an in-memory OAuth2 client store for example purposes.
type ClientManager struct {
	lock    sync.RWMutex
	mgr     *clientauth.Manager
	clients map[string]*sql.Client
}

// NewClientManager returns a ClientManager pre-configured with the none, basic,
// and post client authentication handlers.
func NewClientManager() *ClientManager {
	m := &ClientManager{
		mgr:     clientauth.NewManager(),
		clients: make(map[string]*sql.Client),
	}

	m.mgr.Register(clientauth.NewNoneAuthHandler(m))
	m.mgr.Register(clientauth.NewBasicAuthHandler(m))
	m.mgr.Register(clientauth.NewPostAuthHandler(m))

	return m
}

// Register adds a new client to the manager. If a client with the same
// ClientID already exists, it is overwritten.
func (m *ClientManager) Register(cl *sql.Client) {
	if cl == nil || cl.ClientID == "" {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.clients[cl.ClientID] = cl
}

// QueryByClientID retrieves an OAuth2 client by its client ID.
func (m *ClientManager) QueryByClientID(_ context.Context, id string) (authkitmodels.Client, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	cl, ok := m.clients[id]
	if !ok {
		// Returning (nil, nil) signals authkit that the client was not found,
		// which causes it to respond with an invalid_request error to the caller.
		return nil, nil
	}

	return cl, nil
}

// Authenticate validates the client credentials in the request using the registered auth handlers.
func (m *ClientManager) Authenticate(r *http.Request, authMethods map[authkittypes.ClientAuthMethod]bool, endpointName string) (authkitmodels.Client, error) {
	return m.mgr.Authenticate(r, authMethods, endpointName)
}

// CheckPermission reports whether the client is permitted to introspect the given token.
func (m *ClientManager) CheckPermission(client authkitmodels.Client, token authkitmodels.Token, r *http.Request) bool {
	return true
}
