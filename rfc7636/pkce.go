package rfc7636

import (
	"context"

	autherrors "github.com/alkeyio/authkit/errors"
	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
	"github.com/alkeyio/authkit/utils"
)

// ProofKeyForCodeExchangeFlow implements PKCE (RFC 7636) as an extension for
// the Authorization Code grant. Register it via cfg.RegisterExtension.
type ProofKeyForCodeExchangeFlow struct {
	*Options
}

// New returns a ProofKeyForCodeExchangeFlow with the given Options, or secure
// defaults if none are provided.
func New(opts ...*Options) *ProofKeyForCodeExchangeFlow {
	if len(opts) > 0 && opts[0] != nil {
		return &ProofKeyForCodeExchangeFlow{opts[0]}
	}

	defaultOpts := NewOptions()
	return &ProofKeyForCodeExchangeFlow{defaultOpts}
}

// ValidateAuthorizationRequest checks that the PKCE parameters in the
// authorization request are well-formed. It is a no-op when neither
// code_challenge nor code_challenge_method is present, unless PKCE is required
// for the requesting client (RFC 7636 §4.4.1).
func (f *ProofKeyForCodeExchangeFlow) ValidateAuthorizationRequest(_ context.Context, r *requests.AuthorizationRequest) error {
	// RFC 7636 §4.4.1: if PKCE is required and the client is public (none auth
	// method), code_challenge MUST be present in the authorization request.
	if f.required && !utils.IsNil(r.Client) && r.Client.IsPublic() && r.CodeChallenge == "" {
		return autherrors.InvalidRequestError().WithDescription("this server requires public clients to use PKCE; \"code_challenge\" is missing from the request")
	}

	if r.CodeChallenge == "" && r.CodeChallengeMethod.IsEmpty() {
		return nil
	}

	if r.CodeChallenge == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_challenge\" in request")
	}

	if !r.CodeChallengeMethod.IsEmpty() && !r.CodeChallengeMethod.IsS256() && !r.CodeChallengeMethod.IsPlain() {
		return autherrors.InvalidRequestError().WithDescription("unsupported \"code_challenge_method\"")
	}

	method := r.CodeChallengeMethod
	if method.IsEmpty() {
		method = types.CodeChallengeMethodPlain
	}

	if method.IsPlain() && !f.allowPlain {
		return autherrors.InvalidRequestError().WithDescription("\"plain\" code_challenge_method is not allowed; use S256")
	}

	if method.IsS256() {
		if !ValidateS256CodeChallengePattern(r.CodeChallenge) {
			return autherrors.InvalidRequestError().WithDescription("\"code_challenge\" is not a valid S256 challenge")
		}
	} else if method.IsPlain() {
		if !ValidateCodeVerifierPattern(r.CodeChallenge) {
			return autherrors.InvalidRequestError().WithDescription("\"code_challenge\" does not match plain pattern")
		}
	}

	return nil
}

// ValidateTokenRequest verifies the code_verifier against the stored
// code_challenge. It enforces PKCE for public clients when required is true.
func (f *ProofKeyForCodeExchangeFlow) ValidateTokenRequest(_ context.Context, r *requests.TokenRequest) error {
	if f.required && !utils.IsNil(r.Client) && r.Client.IsPublic() && r.CodeVerifier == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_verifier\" in request")
	}

	if utils.IsNil(r.AuthCode) {
		return autherrors.InvalidRequestError().WithDescription("missing authorization code")
	}

	challenge := r.AuthCode.GetCodeChallenge()
	if challenge == "" && r.CodeVerifier == "" {
		return nil
	}

	if r.CodeVerifier == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_verifier\" in request")
	}

	if valid := ValidateCodeVerifierPattern(r.CodeVerifier); !valid {
		return autherrors.InvalidRequestError().WithDescription("\"code_verifier\" does not match pattern")
	}

	method := r.AuthCode.GetCodeChallengeMethod()
	if method.IsEmpty() {
		// ProcessAuthorizationCode always stores the method explicitly.
		// An empty method means either the auth code was issued without PKCE
		// (challenge also empty) or the stored data has been tampered with
		// (challenge present but method stripped). Reject both to prevent a
		// downgrade attack (RFC 7636 Security Considerations).
		if challenge == "" {
			return autherrors.InvalidGrantError().WithDescription("\"code_verifier\" was sent but the authorization code was not issued with a \"code_challenge\"")
		}
		return autherrors.InvalidGrantError().WithDescription("authorization code is invalid: \"code_challenge_method\" is missing")
	}

	if valid := f.validateCodeVerifier(method, r.CodeVerifier, challenge); !valid {
		return autherrors.InvalidGrantError().WithDescription("code verifier validation failed")
	}

	return nil
}

// ProcessAuthorizationCode stores the PKCE parameters from the authorization
// request into the authorization code before it is persisted.
//
// When code_challenge is present but code_challenge_method is absent, the
// method is stored explicitly as "plain" per RFC 7636 §4.3. Storing an
// explicit value prevents a silent downgrade at token validation time if the
// stored method were ever missing.
func (f *ProofKeyForCodeExchangeFlow) ProcessAuthorizationCode(_ context.Context, r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]any) error {
	if utils.IsNil(authCode) {
		return autherrors.InvalidRequestError().WithDescription("missing authorization code")
	}

	authCode.SetCodeChallenge(r.CodeChallenge)

	method := r.CodeChallengeMethod
	if method.IsEmpty() && r.CodeChallenge != "" {
		// RFC 7636 §4.3: default to plain when omitted by the client.
		// Store explicitly so token validation never needs to guess.
		method = types.CodeChallengeMethodPlain
	}
	authCode.SetCodeChallengeMethod(method)
	return nil
}

// validateCodeVerifier dispatches to the appropriate challenge verifier based
// on the code_challenge_method. Returns false for unknown methods.
func (f *ProofKeyForCodeExchangeFlow) validateCodeVerifier(m types.CodeChallengeMethod, verifier, challenge string) bool {
	if m.IsS256() {
		return f.validateS256Challenge(verifier, challenge)
	}

	if m.IsPlain() {
		return f.validatePlainChallenge(verifier, challenge)
	}

	return false
}

// validatePlainChallenge verifies a plain code_challenge by direct comparison.
func (f *ProofKeyForCodeExchangeFlow) validatePlainChallenge(verifier, challenge string) bool {
	return verifier == challenge
}

// validateS256Challenge verifies an S256 code_challenge by hashing the
// verifier and comparing it to the stored challenge.
func (f *ProofKeyForCodeExchangeFlow) validateS256Challenge(verifier, challenge string) bool {
	return CreateS256CodeChallenge(verifier) == challenge
}
