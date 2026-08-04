package types

// CodeChallengeMethod is the PKCE challenge method used to protect the
// authorization code (RFC 7636 §4.3). Supported values are "plain" and "S256".
// "S256" is strongly preferred; "plain" should only be used when the client
// cannot support S256.
type CodeChallengeMethod string

func NewCodeChallengeMethod(s string) CodeChallengeMethod {
	return CodeChallengeMethod(s)
}

func (m CodeChallengeMethod) Equal(o CodeChallengeMethod) bool {
	return m == o
}

func (m CodeChallengeMethod) IsPlain() bool {
	return m.Equal(CodeChallengeMethodPlain)
}

func (m CodeChallengeMethod) IsS256() bool {
	return m.Equal(CodeChallengeMethodS256)
}

func (m CodeChallengeMethod) IsEmpty() bool {
	return m.Equal("")
}

func (m CodeChallengeMethod) String() string {
	return string(m)
}
