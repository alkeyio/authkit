package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContentType(t *testing.T) {
	ct := NewContentType("text/plain")
	assert.IsType(t, ContentType(""), ct)
	assert.Equal(t, "text/plain", ct.String())
	assert.False(t, ct.IsJSON())
	assert.False(t, ct.IsXWWWFormUrlencoded())

	assert.True(t, ContentTypeJSON.IsJSON())
	assert.False(t, ContentTypeJSON.IsXWWWFormUrlencoded())

	assert.True(t, ContentTypeXWWWFormUrlencoded.IsXWWWFormUrlencoded())
	assert.False(t, ContentTypeXWWWFormUrlencoded.IsJSON())
}
