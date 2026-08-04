package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrantType(t *testing.T) {
	g := NewGrantType("custom")
	assert.IsType(t, GrantType(""), g)
	assert.Equal(t, "custom", g.String())
	assert.False(t, g.IsEmpty())
	assert.True(t, NewGrantType("").IsEmpty())

	assert.True(t, g.Equal(NewGrantType("custom")))
	assert.False(t, g.Equal(GrantTypeAuthorizationCode))

	assert.True(t, GrantTypeAuthorizationCode.IsAuthorizationCode())
	assert.True(t, GrantTypeClientCredentials.IsClientCredentials())
	assert.True(t, GrantTypeROPC.IsROPC())
	assert.True(t, GrantTypeRefreshToken.IsRefreshToken())

	assert.False(t, GrantTypeAuthorizationCode.IsROPC())
	assert.False(t, GrantTypeROPC.IsRefreshToken())
}

func TestGrantTypes(t *testing.T) {
	gts := NewGrantTypes([]string{"authorization_code", "refresh_token"})
	assert.True(t, gts.Contains(GrantTypeAuthorizationCode))
	assert.True(t, gts.Contains(GrantTypeRefreshToken))
	assert.False(t, gts.Contains(GrantTypeROPC))
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, gts.String())
}

func TestResponseType(t *testing.T) {
	r := NewResponseType("custom")
	assert.IsType(t, ResponseType(""), r)
	assert.Equal(t, "custom", r.String())
	assert.False(t, r.IsEmpty())
	assert.True(t, NewResponseType("").IsEmpty())
	assert.False(t, r.IsValid())

	assert.True(t, r.Equal(NewResponseType("custom")))
	assert.False(t, r.Equal(ResponseTypeCode))

	assert.True(t, ResponseTypeCode.IsCode())
	assert.False(t, ResponseTypeCode.IsToken())
	assert.True(t, ResponseTypeCode.IsValid())

	assert.True(t, ResponseTypeToken.IsToken())
	assert.False(t, ResponseTypeToken.IsCode())
	assert.True(t, ResponseTypeToken.IsValid())
}

func TestResponseTypes(t *testing.T) {
	rts := NewResponseTypes([]string{"code", "token"})
	assert.Equal(t, []string{"code", "token"}, rts.String())
}
