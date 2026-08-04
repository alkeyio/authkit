package clientauth

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	autherrors "github.com/tniah/authkit/errors"
	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/types"
)

// Manager dispatches client authentication to the appropriate Handler based on
// the authentication method. Each grant flow holds a Manager and passes its
// supportedMethods to Authenticate so that only permitted methods are tried.
type Manager struct {
	handlers map[types.ClientAuthMethod]Handler
}

// NewManager creates an empty Manager. Call Register to add authentication handlers
// before use.
func NewManager() *Manager {
	return &Manager{
		handlers: make(map[types.ClientAuthMethod]Handler),
	}
}

// Authenticate iterates over supportedMethods and delegates to the matching
// registered Handler. The first handler that returns a valid client whose
// registered auth method matches the attempted method wins.
//
// Returns ErrInvalidClient if no handler succeeds.
func (m *Manager) Authenticate(r *http.Request, supportedMethods map[types.ClientAuthMethod]bool, endpoint string) (models.Client, error) {
	for method, ok := range supportedMethods {
		if !ok {
			continue
		}

		var h Handler
		if h, ok = m.handlers[method]; !ok {
			continue
		}

		client, err := h.Authenticate(r)
		if err != nil {
			continue
		}

		if client != nil && client.CheckTokenEndpointAuthMethod(method, endpoint) {
			return client, nil
		}
	}

	methods := make([]string, 0, len(supportedMethods))
	for method, ok := range supportedMethods {
		if ok {
			methods = append(methods, fmt.Sprintf("%q", string(method)))
		}
	}
	sort.Strings(methods)

	authErr := autherrors.InvalidClientError().WithDescription(
		fmt.Sprintf("The client failed to authenticate using any of the following methods: [%s]", strings.Join(methods, ", ")),
	)

	if supportedMethods[types.ClientBasicAuthentication] {
		authErr.SetHttpCode(http.StatusUnauthorized)
	}

	return nil, authErr
}

// Register adds h to the manager, keyed by h.Method(). Registering a handler
// for an already-registered method replaces the previous one.
func (m *Manager) Register(h Handler) {
	if m.handlers == nil {
		m.handlers = make(map[types.ClientAuthMethod]Handler)
	}

	m.handlers[h.Method()] = h
}
