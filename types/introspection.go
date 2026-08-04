package types

// TokenTypeHint is an optional hint about the type of token submitted to the
// introspection endpoint (RFC 7662 §2.1). Unknown hint values must be silently
// ignored by the server.
type TokenTypeHint string

func NewTokenTypeHint(s string) TokenTypeHint {
	return TokenTypeHint(s)
}

func (t TokenTypeHint) IsEmpty() bool {
	return t == ""
}

func (t TokenTypeHint) IsAccessToken() bool {
	return t == TokenTypeHintAccessToken
}

func (t TokenTypeHint) IsRefreshToken() bool {
	return t == TokenTypeHintRefreshToken
}

func (t TokenTypeHint) IsValid() bool {
	return t.IsAccessToken() || t.IsRefreshToken()
}

func (t TokenTypeHint) String() string {
	return string(t)
}
