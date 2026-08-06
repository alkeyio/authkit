package rfc6749

// OmittedScopePolicy controls how a grant flow endpoint behaves when the
// client does not include a scope parameter in the request (RFC 6749 §3.3).
//
// Each grant flow package (authorization_code, client_credentials, ropc)
// re-exports this type as a local alias so callers can reference it through
// the package they already import.
type OmittedScopePolicy int

const (
	// OmittedScopePolicyReject rejects the request with invalid_scope when
	// the scope parameter is absent. This is the default for all grant flows.
	OmittedScopePolicyReject OmittedScopePolicy = iota

	// OmittedScopePolicyUseClientDefault grants the client's full registered
	// scope list when the scope parameter is absent.
	OmittedScopePolicyUseClientDefault
)
