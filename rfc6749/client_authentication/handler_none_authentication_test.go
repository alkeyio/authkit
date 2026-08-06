package clientauth

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alkeyio/authkit/integrations/sql"
	rfc6749 "github.com/alkeyio/authkit/mocks/rfc6749/client_authentication"
	"github.com/alkeyio/authkit/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewNoneAuthHandler(t *testing.T) {
	store := rfc6749.NewMockClientStore(t)
	h := NewNoneAuthHandler(store)
	assert.NotNil(t, h)
	assert.NotNil(t, h.store)
}

func TestMustNoneAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h, err := MustNoneAuthHandler(store)
		assert.NoError(t, err)
		assert.NotNil(t, h)
	})

	t.Run("error_nil_store", func(t *testing.T) {
		h, err := MustNoneAuthHandler(nil)
		assert.Nil(t, h)
		assert.ErrorIs(t, err, ErrNilClientStore)
	})
}

func TestNoneAuthHandler_Method(t *testing.T) {
	store := rfc6749.NewMockClientStore(t)
	h := NewNoneAuthHandler(store)
	assert.Equal(t, types.ClientNoneAuthentication, h.Method())
}

func TestNoneAuthHandler_Authenticate(t *testing.T) {
	const clientID = "public-client"

	mockClient := &sql.Client{
		ClientID:                clientID,
		TokenEndpointAuthMethod: types.ClientNoneAuthentication.String(),
	}

	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(mockClient, nil).Once()

		h := NewNoneAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", strings.NewReader("client_id="+clientID))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.NoError(t, err)
		assert.Equal(t, mockClient, client)
	})

	t.Run("error_not_post_method", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewNoneAuthHandler(store)
		r := httptest.NewRequest("GET", "/token", nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_wrong_content_type", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewNoneAuthHandler(store)
		body := `{"client_id":"` + clientID + `"}`
		r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_missing_client_id", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h := NewNoneAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", strings.NewReader("grant_type=authorization_code"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("error_store_returns_error", func(t *testing.T) {
		storeErr := errors.New("db error")
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(nil, storeErr).Once()

		h := NewNoneAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", strings.NewReader("client_id="+clientID))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, storeErr)
	})

	t.Run("error_client_not_found", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		store.On("QueryByClientID", mock.Anything, clientID).Return(nil, nil).Once()

		h := NewNoneAuthHandler(store)
		r := httptest.NewRequest("POST", "/token", strings.NewReader("client_id="+clientID))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client, err := h.Authenticate(r)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})
}
