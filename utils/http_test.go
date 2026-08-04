package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/alkeyio/authkit/types"
)

func TestContentType(t *testing.T) {
	t.Run("parses_json_content_type", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Content-Type", "application/json; charset=UTF-8")

		ct, err := ContentType(r)
		assert.NoError(t, err)
		assert.Equal(t, types.NewContentType("application/json"), ct)
	})

	t.Run("parses_form_content_type", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ct, err := ContentType(r)
		assert.NoError(t, err)
		assert.Equal(t, types.ContentTypeXWWWFormUrlencoded, ct)
	})

	t.Run("error_when_header_missing", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		_, err := ContentType(r)
		assert.Error(t, err)
	})

	t.Run("error_when_header_malformed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Content-Type", ";;;")
		_, err := ContentType(r)
		assert.Error(t, err)
	})
}

func TestJSONHeaders(t *testing.T) {
	h := JSONHeaders()
	assert.Equal(t, types.ContentTypeJSON.String(), h["Content-Type"])
	assert.Equal(t, "no-store", h["Cache-Control"])
	assert.Equal(t, "no-cache", h["Pragma"])
}

func TestJSONResponse(t *testing.T) {
	t.Run("default_200_status", func(t *testing.T) {
		rw := httptest.NewRecorder()
		payload := map[string]interface{}{"foo": "bar"}

		err := JSONResponse(rw, payload)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, types.ContentTypeJSON.String(), rw.Header().Get("Content-Type"))

		var got map[string]interface{}
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&got))
		assert.Equal(t, "bar", got["foo"])
	})

	t.Run("custom_status_code", func(t *testing.T) {
		rw := httptest.NewRecorder()
		err := JSONResponse(rw, map[string]interface{}{}, http.StatusBadRequest)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})
}

func TestAddParamsToURI(t *testing.T) {
	t.Run("appends_params_to_uri", func(t *testing.T) {
		uri, err := AddParamsToURI("https://example.com/cb", map[string]interface{}{
			"code":  "abc123",
			"state": "xyz",
		})
		assert.NoError(t, err)

		parsed, err := http.NewRequest(http.MethodGet, uri, nil)
		require.NoError(t, err)
		assert.Equal(t, "abc123", parsed.URL.Query().Get("code"))
		assert.Equal(t, "xyz", parsed.URL.Query().Get("state"))
	})

	t.Run("preserves_existing_query_params", func(t *testing.T) {
		uri, err := AddParamsToURI("https://example.com/cb?existing=1", map[string]interface{}{
			"new": "2",
		})
		assert.NoError(t, err)

		parsed, err := http.NewRequest(http.MethodGet, uri, nil)
		require.NoError(t, err)
		assert.Equal(t, "1", parsed.URL.Query().Get("existing"))
		assert.Equal(t, "2", parsed.URL.Query().Get("new"))
	})

	t.Run("error_on_invalid_uri", func(t *testing.T) {
		_, err := AddParamsToURI("://bad uri", map[string]interface{}{})
		assert.Error(t, err)
	})
}

func TestRedirect(t *testing.T) {
	t.Run("sets_302_and_location_header", func(t *testing.T) {
		rw := httptest.NewRecorder()
		err := Redirect(rw, "https://example.com/cb", map[string]interface{}{
			"code": "abc123",
		})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rw.Code)

		location := rw.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/cb")
		assert.Contains(t, location, "code=abc123")
	})

	t.Run("error_on_invalid_uri", func(t *testing.T) {
		rw := httptest.NewRecorder()
		err := Redirect(rw, "://bad uri", map[string]interface{}{})
		assert.Error(t, err)
	})
}
