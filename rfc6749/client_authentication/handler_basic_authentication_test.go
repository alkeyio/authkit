package clientauth

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/alkeyio/authkit/integrations/sql"
	rfc6749 "github.com/alkeyio/authkit/mocks/rfc6749/client_authentication"
	"github.com/alkeyio/authkit/types"
)

func TestNewBasicAuthHandler(t *testing.T) {
	store := rfc6749.NewMockClientStore(t)
	h := NewBasicAuthHandler(store)
	assert.NotNil(t, h)
	assert.NotNil(t, h.store)
}

func TestMustBasicAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h, err := MustBasicAuthHandler(store)
		assert.NoError(t, err)
		assert.NotNil(t, h)
	})

	t.Run("error_nil_store", func(t *testing.T) {
		h, err := MustBasicAuthHandler(nil)
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrNilClientStore)
	})
}

func TestBasicAuthHandler_Method(t *testing.T) {
	store := rfc6749.NewMockClientStore(t)
	h := NewBasicAuthHandler(store)
	assert.Equal(t, types.ClientBasicAuthentication, h.Method())
}

func TestBasicAuthHandler_Authenticate(t *testing.T) {
	const (
		clientID     = "test-client"
		clientSecret = "correct-secret"
	)

	mockClient := &sql.Client{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		TokenEndpointAuthMethod: types.ClientBasicAuthentication.String(),
	}

	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(mockClient, nil).Once()

		h := NewBasicAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", nil)
		r.SetBasicAuth(clientID, clientSecret)

		client, err := h.Authenticate(r)
		assert.NoError(t, err)
		assert.Equal(t, mockClient, client)
	})

	t.Run("error_no_auth_header", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewBasicAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", nil)

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_empty_client_id", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewBasicAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", nil)
		r.SetBasicAuth("", clientSecret)

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_store_returns_error", func(t *testing.T) {
		storeErr := errors.New("db error")
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(nil, storeErr).Once()

		h := NewBasicAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", nil)
		r.SetBasicAuth(clientID, clientSecret)

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, storeErr)
	})

	t.Run("error_client_not_found", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(nil, nil).Once()

		h := NewBasicAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", nil)
		r.SetBasicAuth(clientID, clientSecret)

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_wrong_secret", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(mockClient, nil).Once()

		h := NewBasicAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", nil)
		r.SetBasicAuth(clientID, "wrong-secret")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})
}
