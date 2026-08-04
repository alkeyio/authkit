package errors

import (
	"fmt"
	"net/http"
)

// OAuth2Error represents an OAuth 2.0 error response as defined in RFC 6749 §5.2.
// It carries the error code, human-readable description, optional URI, the HTTP
// status code to send, and any extra response headers (e.g. WWW-Authenticate).
type OAuth2Error struct {
	// Code is the short error code string mandated by RFC 6749 (e.g. "invalid_client").
	// Use one of the sentinel errors defined in constants.go as the value.
	Code error

	// Description is a human-readable explanation of the error, included in the
	// response as "error_description". Defaults to the value in Descriptions if not set.
	Description string

	// URI is an optional URI pointing to a human-readable error page, included in
	// the response as "error_uri".
	URI string

	// HttpCode is the HTTP status code to send with this error response.
	// Populated automatically from HttpCodes based on Code.
	HttpCode int

	// HttpHeader holds extra HTTP headers to include in the error response,
	// for example WWW-Authenticate for client_secret_basic failures.
	HttpHeader http.Header
}

// NewOAuth2Error creates an OAuth2Error for the given error code. Optional args
// set Description (args[0]) and URI (args[1]). The HTTP status code is looked up
// from HttpCodes; unknown codes default to 400 Bad Request.
func NewOAuth2Error(code error, args ...string) *OAuth2Error {
	httpCode := http.StatusBadRequest
	if v, ok := HttpCodes[code]; ok {
		httpCode = v
	}

	e := &OAuth2Error{
		Code:       code,
		HttpCode:   httpCode,
		HttpHeader: make(http.Header),
	}

	if len(args) > 0 {
		e.Description = args[0]
	}

	if len(args) > 1 {
		e.URI = args[1]
	}

	if e.Description == "" {
		if v, ok := Descriptions[code]; ok {
			e.Description = v
		}
	}

	return e
}

// Error implements the error interface.
func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("error=%v, description=%s", e.Code, e.Description)
}

// SetHttpCode overrides the HTTP status code determined automatically from
// HttpCodes. Use only when a specific RFC or custom requirement calls for a
// status code that differs from the default mapping.
func (e *OAuth2Error) SetHttpCode(code int) {
	e.HttpCode = code
}

// SetHeader adds an HTTP response header to this error. Useful for protocol-level
// headers such as WWW-Authenticate that must accompany the error response.
func (e *OAuth2Error) SetHeader(key, value string) {
	if e.HttpHeader == nil {
		e.HttpHeader = make(http.Header)
	}

	e.HttpHeader.Set(key, value)
}

// Data returns the JSON-serializable body for the error response. It always
// includes "error"; "error_description" and "error_uri" are omitted when empty.
func (e *OAuth2Error) Data() map[string]interface{} {
	data := map[string]interface{}{
		ErrCode: fmt.Sprintf("%v", e.Code),
	}

	if v := e.Description; v != "" {
		data[ErrDescription] = v
	}

	if v := e.URI; v != "" {
		data[ErrURI] = v
	}

	return data
}

// Response returns the HTTP status code, headers, and JSON body needed to write
// the error response. Consumed by AuthKitError.Response and Server.HandleError.
func (e *OAuth2Error) Response() (statusCode int, header http.Header, data map[string]interface{}) {
	return e.HttpCode, e.HttpHeader, e.Data()
}
