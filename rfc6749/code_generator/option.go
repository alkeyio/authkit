package codegen

import (
	"time"
)

const (
	// DefaultExpiresIn is the authorization code lifetime used when no
	// ExpiresInGenerator is configured. RFC 6749 §4.1.2 recommends a
	// maximum of 10 minutes; 5 minutes is chosen as a secure default.
	DefaultExpiresIn = 5 * time.Minute

	// DefaultCodeLength is the number of alphanumeric characters in a
	// generated code. 48 characters over a 62-symbol alphabet yields
	// ≈285 bits of entropy, well above the 128-bit minimum required by
	// RFC 6749 §10.5.
	DefaultCodeLength = 48
)

// Options holds the configuration for a Generator. Use NewOptions to obtain
// a value with secure defaults, then chain Set* calls before passing to New.
type Options struct {
	codeLength          int
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
	extraDataGenerator  ExtraDataGenerator
}

// NewOptions returns Options with DefaultCodeLength and DefaultExpiresIn.
// All generator hooks are nil, meaning the built-in crypto/rand implementation
// and the static expiry are used.
func NewOptions() *Options {
	return &Options{
		codeLength: DefaultCodeLength,
		expiresIn:  DefaultExpiresIn,
	}
}

// SetCodeLength overrides the length of the generated code string.
// Values less than 1 will cause ErrInvalidCodeLength at generation time.
func (opts *Options) SetCodeLength(length int) *Options {
	opts.codeLength = length
	return opts
}

// SetExpiresIn overrides the static code lifetime used when no
// ExpiresInGenerator is configured.
func (opts *Options) SetExpiresIn(l time.Duration) *Options {
	opts.expiresIn = l
	return opts
}

// SetExpiresInGenerator registers a per-request expiry hook. When set it
// takes precedence over the static expiresIn value. Pass nil to revert to
// the static value.
func (opts *Options) SetExpiresInGenerator(fn ExpiresInGenerator) *Options {
	opts.expiresInGenerator = fn
	return opts
}

// SetRandStringGenerator registers a custom code-generation hook. When set
// it replaces the built-in crypto/rand implementation entirely. Pass nil to
// revert to the default.
func (opts *Options) SetRandStringGenerator(fn RandStringGenerator) *Options {
	opts.randStringGenerator = fn
	return opts
}

// SetExtraDataGenerator registers a hook that attaches arbitrary metadata to
// the authorization code (e.g. PKCE challenge, session ID). Pass nil to
// disable extra-data generation.
func (opts *Options) SetExtraDataGenerator(fn ExtraDataGenerator) *Options {
	opts.extraDataGenerator = fn
	return opts
}
