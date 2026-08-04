package utils

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"

	"github.com/alkeyio/authkit/types"
)

// ContentType parses the Content-Type header from r and returns it as a
// types.ContentType. Returns an error if the header is missing or malformed.
func ContentType(r *http.Request) (types.ContentType, error) {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return "", err
	}

	return types.NewContentType(ct), nil
}

// JSONHeaders returns the standard HTTP headers for a JSON response:
// Content-Type, Cache-Control, and Pragma.
func JSONHeaders() map[string]string {
	return map[string]string{
		"Content-Type":  types.ContentTypeJSON.String(),
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
	}
}

// JSONResponse writes a JSON-encoded payload to rw with the standard JSON
// headers. The optional status argument sets the HTTP status code; it defaults
// to 200 OK.
func JSONResponse(rw http.ResponseWriter, payload map[string]interface{}, status ...int) error {
	for k, v := range JSONHeaders() {
		rw.Header().Set(k, v)
	}

	st := http.StatusOK
	if len(status) > 0 {
		st = status[0]
	}
	rw.WriteHeader(st)

	return json.NewEncoder(rw).Encode(payload)
}

// AddParamsToURI appends params as query string parameters to uri and returns
// the resulting URL string.
func AddParamsToURI(uri string, params map[string]interface{}) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, fmt.Sprint(v))
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// Redirect writes a 302 redirect response to rw, appending params to uri as
// query string parameters.
func Redirect(rw http.ResponseWriter, uri string, params map[string]interface{}) error {
	location, err := AddParamsToURI(uri, params)
	if err != nil {
		return err
	}

	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusFound)
	return nil
}
