package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientAuthMethod(t *testing.T) {
	m := NewClientAuthMethod("test")
	assert.IsType(t, (ClientAuthMethod)(""), m)
	assert.Equal(t, "test", m.String())

	assert.False(t, m.Equal(ClientBasicAuthentication))
	assert.True(t, m.Equal(NewClientAuthMethod("test")))

	assert.True(t, ClientBasicAuthentication.IsBasic())
	assert.True(t, ClientPostAuthentication.IsPOST())
	assert.True(t, ClientNoneAuthentication.IsNone())
	assert.True(t, NewClientAuthMethod("").IsEmpty())
	assert.False(t, m.IsEmpty())
}
