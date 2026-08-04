package types

import "golang.org/x/text/language"

// Scope is a single OAuth 2.0 / OpenID Connect scope value (RFC 6749 §3.3).
type Scope string

func NewScope(s string) Scope {
	return Scope(s)
}

func (s Scope) Equal(o Scope) bool {
	return s == o
}

func (s Scope) IsOpenID() bool {
	return s.Equal(ScopeOpenID)
}

func (s Scope) IsEmpty() bool {
	return s.Equal("")
}

func (s Scope) String() string {
	return string(s)
}

// Scopes is a slice of Scope.
type Scopes []Scope

func NewScopes(ar []string) Scopes {
	ret := make(Scopes, len(ar))
	for i, s := range ar {
		ret[i] = NewScope(s)
	}
	return ret
}

func (s Scopes) Contain(expected Scope) bool {
	for _, scope := range s {
		if scope == expected {
			return true
		}
	}

	return false
}

func (s Scopes) ContainOpenID() bool {
	return s.Contain(ScopeOpenID)
}

func (s Scopes) String() []string {
	ret := make([]string, len(s))
	for i, scope := range s {
		ret[i] = string(scope)
	}
	return ret
}

// Display controls how the authorization server presents the authentication UI
// to the end-user (OpenID Connect Core §3.1.2.1).
type Display string

func NewDisplay(s string) Display {
	return Display(s)
}

func (d Display) IsPage() bool {
	return d == DisplayPage
}

func (d Display) IsPopup() bool {
	return d == DisplayPopup
}

func (d Display) IsTouch() bool {
	return d == DisplayTouch
}

func (d Display) IsWap() bool {
	return d == DisplayWap
}

func (d Display) IsValid() bool {
	return d.IsPage() || d.IsPopup() || d.IsTouch() || d.IsWap()
}

func (d Display) IsEmpty() bool {
	return d == ""
}

func (d Display) String() string {
	return string(d)
}

// Prompt specifies whether the authorization server should prompt the
// end-user for re-authentication or consent (OpenID Connect Core §3.1.2.1).
type Prompt string

func NewPrompt(s string) Prompt {
	return Prompt(s)
}

func (p Prompt) IsNone() bool {
	return p == PromptNone
}

func (p Prompt) IsLogin() bool {
	return p == PromptLogin
}

func (p Prompt) IsConsent() bool {
	return p == PromptConsent
}

func (p Prompt) IsSelectAccount() bool {
	return p == PromptSelectAccount
}

func (p Prompt) IsValid() bool {
	return p.IsNone() || p.IsLogin() || p.IsConsent() || p.IsSelectAccount()
}

func (p Prompt) String() string {
	return string(p)
}

// Prompts is a slice of Prompt parsed from the space-delimited prompt parameter.
type Prompts []Prompt

func NewPrompts(ar []string) Prompts {
	ret := make([]Prompt, len(ar))
	for i, s := range ar {
		ret[i] = NewPrompt(s)
	}
	return ret
}

func (p Prompts) Contain(expected Prompt) bool {
	for _, prompt := range p {
		if prompt == expected {
			return true
		}
	}

	return false
}

func (p Prompts) ContainLogin() bool {
	return p.Contain(PromptLogin)
}

func (p Prompts) ContainNone() bool {
	return p.Contain(PromptNone)
}

func (p Prompts) ContainConsent() bool {
	return p.Contain(PromptConsent)
}

func (p Prompts) ContainSelectAccount() bool {
	return p.Contain(PromptSelectAccount)
}

func (p Prompts) String() []string {
	ret := make([]string, len(p))
	for i, s := range p {
		ret[i] = string(s)
	}
	return ret
}

// MaxAge is the maximum elapsed time in seconds since the last active
// authentication (OpenID Connect Core §3.1.2.1). A nil value means no
// max_age constraint was specified.
type MaxAge *uint

func NewMaxAge(i uint) MaxAge {
	return &i
}

// Locales is an ordered list of BCP 47 language tags representing the
// end-user's preferred UI locales (OpenID Connect Core §3.1.2.1).
// Invalid or root tags are silently dropped during parsing.
type Locales []language.Tag

func NewLocales(locales []string) Locales {
	out := make(Locales, 0, len(locales))
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			out = append(out, tag)
		}
	}
	return out
}

// ResponseMode specifies how the authorization server returns the authorization
// response to the client (RFC 9207).
type ResponseMode string

func NewResponseMode(s string) ResponseMode {
	return ResponseMode(s)
}

func (m ResponseMode) IsEmpty() bool {
	return m == ""
}

func (m ResponseMode) String() string {
	return string(m)
}
