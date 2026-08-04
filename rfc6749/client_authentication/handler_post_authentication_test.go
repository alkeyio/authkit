package clientauth

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authkit/integrations/sql"
	rfc6749 "github.com/tniah/authkit/mocks/rfc6749/client_authentication"
	"github.com/tniah/authkit/types"
)

func TestNewPostAuthHandler(t *testing.T) {
	store := rfc6749.NewMockClientStore(t)
	h := NewPostAuthHandler(store)
	assert.NotNil(t, h)
	assert.NotNil(t, h.store)
}

func TestMustPostAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h, err := MustPostAuthHandler(store)
		assert.NoError(t, err)
		assert.NotNil(t, h)
	})

	t.Run("error_nil_store", func(t *testing.T) {
		h, err := MustPostAuthHandler(nil)
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrNilClientStore)
	})
}

func TestPostAuthHandler_Method(t *testing.T) {
	store := rfc6749.NewMockClientStore(t)
	h := NewPostAuthHandler(store)
	assert.Equal(t, types.ClientPostAuthentication, h.Method())
}

func TestPostAuthHandler_Authenticate(t *testing.T) {
	const (
		clientID     = "test-client"
		clientSecret = "correct-secret"
	)

	mockClient := &sql.Client{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		TokenEndpointAuthMethod: types.ClientPostAuthentication.String(),
	}

	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(mockClient, nil).Once()

		h := NewPostAuthHandler(store)
		body := "client_id=" + clientID + "&client_secret=" + clientSecret
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.NoError(t, err)
		assert.Equal(t, mockClient, client)
	})

	t.Run("error_not_post_method", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewPostAuthHandler(store)
		r := httptest.NewRequest("GET", "/token", nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_wrong_content_type", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewPostAuthHandler(store)
		body := `{"client_id":"` + clientID + `","client_secret":"` + clientSecret + `"}`
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_missing_client_id", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewPostAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", strings.NewReader("client_secret="+clientSecret))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_store_returns_error", func(t *testing.T) {
		storeErr := errors.New("db error")
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(nil, storeErr).Once()

		h := NewPostAuthHandler(store)
		body := "client_id=" + clientID + "&client_secret=" + clientSecret
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, storeErr)
	})

	t.Run("error_client_not_found", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(nil, nil).Once()

		h := NewPostAuthHandler(store)
		body := "client_id=" + clientID + "&client_secret=" + clientSecret
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_wrong_secret", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(mockClient, nil).Once()

		h := NewPostAuthHandler(store)
		body := "client_id=" + clientID + "&client_secret=wrong-secret"
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})
}
