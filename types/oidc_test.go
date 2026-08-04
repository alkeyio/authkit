package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScope(t *testing.T) {
	s := NewScope("test")
	assert.IsType(t, Scope(""), s)

	assert.False(t, s.IsEmpty())
	assert.Equal(t, "test", s.String())
	assert.True(t, ScopeOpenID.IsOpenID())
	assert.False(t, s.IsOpenID())
}

func TestScopes(t *testing.T) {
	scopes := NewScopes([]string{"openid", "profile"})
	assert.True(t, scopes.ContainOpenID())
	assert.False(t, scopes.Contain("test"))

	assert.Equal(t, []string{"openid", "profile"}, scopes.String())
}

func TestDisplay(t *testing.T) {
	d := NewDisplay("custom")
	assert.IsType(t, Display(""), d)
	assert.Equal(t, "custom", d.String())
	assert.False(t, d.IsValid())
	assert.False(t, d.IsEmpty())
	assert.True(t, NewDisplay("").IsEmpty())

	assert.True(t, DisplayPage.IsPage())
	assert.True(t, DisplayPage.IsValid())
	assert.True(t, DisplayPopup.IsPopup())
	assert.True(t, DisplayPopup.IsValid())
	assert.True(t, DisplayTouch.IsTouch())
	assert.True(t, DisplayTouch.IsValid())
	assert.True(t, DisplayWap.IsWap())
	assert.True(t, DisplayWap.IsValid())

	assert.False(t, DisplayPage.IsPopup())
}

func TestPrompt(t *testing.T) {
	p := NewPrompt("custom")
	assert.IsType(t, Prompt(""), p)
	assert.Equal(t, "custom", p.String())
	assert.False(t, p.IsValid())

	assert.True(t, PromptNone.IsNone())
	assert.True(t, PromptNone.IsValid())
	assert.True(t, PromptLogin.IsLogin())
	assert.True(t, PromptLogin.IsValid())
	assert.True(t, PromptConsent.IsConsent())
	assert.True(t, PromptConsent.IsValid())
	assert.True(t, PromptSelectAccount.IsSelectAccount())
	assert.True(t, PromptSelectAccount.IsValid())

	assert.False(t, PromptNone.IsLogin())
}

func TestPrompts(t *testing.T) {
	ps := NewPrompts([]string{"none", "login", "consent", "select_account"})
	assert.True(t, ps.ContainNone())
	assert.True(t, ps.ContainLogin())
	assert.True(t, ps.ContainConsent())
	assert.True(t, ps.ContainSelectAccount())
	assert.False(t, ps.Contain("custom"))
	assert.Equal(t, []string{"none", "login", "consent", "select_account"}, ps.String())
}

func TestMaxAge(t *testing.T) {
	m := NewMaxAge(300)
	assert.NotNil(t, m)
	assert.Equal(t, uint(300), *m)
}

func TestLocales(t *testing.T) {
	l := NewLocales([]string{"en", "vi", "!!!"})
	assert.Len(t, l, 2)

	assert.Empty(t, NewLocales([]string{}))
}

func TestResponseMode(t *testing.T) {
	m := NewResponseMode("query")
	assert.IsType(t, ResponseMode(""), m)
	assert.Equal(t, "query", m.String())
	assert.False(t, m.IsEmpty())
	assert.True(t, NewResponseMode("").IsEmpty())
}
