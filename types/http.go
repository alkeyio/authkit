package types

// ContentType represents an HTTP Content-Type header value.
type ContentType string

func NewContentType(s string) ContentType {
	return ContentType(s)
}

func (t ContentType) IsJSON() bool {
	return t == ContentTypeJSON
}

func (t ContentType) IsXWWWFormUrlencoded() bool {
	return t == ContentTypeXWWWFormUrlencoded
}

func (t ContentType) String() string {
	return string(t)
}
