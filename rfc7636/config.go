package rfc7636

// Options configures PKCE (Proof Key for Code Exchange, RFC 7636) behavior.
type Options struct {
	// required forces public clients (none auth method) to always include a
	// code_verifier. Set to false to allow PKCE to be optional.
	required bool
	// allowPlain controls whether the "plain" code_challenge_method is accepted.
	// RFC 9700 §2.1 states S256 MUST be used; set to false to enforce S256-only.
	allowPlain bool
}

// NewOptions returns Options with defaults:
//   - PKCE is required for public clients.
//   - plain code_challenge_method is allowed (RFC 7636 compatible). Call
//     SetAllowPlain(false) to enforce S256-only per RFC 9700 §2.1.
func NewOptions() *Options {
	return &Options{
		required:   true,
		allowPlain: true,
	}
}

// SetRequired controls whether PKCE is mandatory for public clients.
func (opts *Options) SetRequired(value bool) *Options {
	opts.required = value
	return opts
}

// SetAllowPlain controls whether the "plain" code_challenge_method is accepted.
// Set to false to enforce S256-only per RFC 9700 §2.1.
func (opts *Options) SetAllowPlain(value bool) *Options {
	opts.allowPlain = value
	return opts
}
