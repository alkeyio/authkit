package types

// ClientAuthMethod is the authentication method a client uses at the token
// endpoint (RFC 6749 §2.3). Common values are "client_secret_basic",
// "client_secret_post", and "none" (public clients).
type ClientAuthMethod string

func NewClientAuthMethod(method string) ClientAuthMethod {
	return ClientAuthMethod(method)
}

func (m ClientAuthMethod) Equal(o ClientAuthMethod) bool {
	return m == o
}

func (m ClientAuthMethod) IsBasic() bool {
	return m.Equal(ClientBasicAuthentication)
}

func (m ClientAuthMethod) IsPOST() bool {
	return m.Equal(ClientPostAuthentication)
}

func (m ClientAuthMethod) IsNone() bool {
	return m.Equal(ClientNoneAuthentication)
}

func (m ClientAuthMethod) IsEmpty() bool {
	return m.Equal("")
}

func (m ClientAuthMethod) String() string {
	return string(m)
}
