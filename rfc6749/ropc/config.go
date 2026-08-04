package ropc

import (
	"errors"
	"net/http"

	"github.com/tniah/authkit/types"
	"github.com/tniah/authkit/utils"
)

// Sentinel errors returned by ValidateConfig when a required dependency is missing.
var (
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilUserManager         = errors.New("user manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("client auth methods are empty")
)

// OmittedScopePolicy controls how the token endpoint behaves when the client
// does not include a scope parameter in the request (RFC 6749 §3.3).
type OmittedScopePolicy int

const (
	// OmittedScopePolicyReject rejects the request with invalid_scope when
	// the scope parameter is absent. This is the default.
	OmittedScopePolicyReject OmittedScopePolicy = iota

	// OmittedScopePolicyUseClientDefault grants the client's full registered
	// scope list when the scope parameter is absent.
	OmittedScopePolicyUseClientDefault
)

// Config holds all dependencies and extension hooks for the ROPC flow.
// Use NewConfig() to get a config with sensible defaults, then chain Set*/RegisterExtension
// calls before passing to Must() or New().
type Config struct {
	clientMgr ClientManager
	userMgr   UserManager
	tokenMgr  TokenManager

	tokenEndpointHttpMethods []string

	// Extension slices are executed in registration order.
	tokenReqValidators []TokenRequestValidator
	tokenProcessors    []TokenProcessor

	// supportedClientAuthMethods controls which client authentication methods
	// are accepted at the token endpoint. ROPC defaults to basic auth only.
	supportedClientAuthMethods map[types.ClientAuthMethod]bool

	// omittedScopePolicy controls the behavior when the client omits the scope
	// parameter (RFC 6749 §3.3). Default: OmittedScopePolicyReject.
	omittedScopePolicy OmittedScopePolicy
}

// NewConfig returns a Config with secure defaults:
//   - Accepts POST on /token.
//   - Supports basic client authentication only (client_secret_basic).
//   - Omitted scope: reject with invalid_scope (OmittedScopePolicyReject).
func NewConfig() *Config {
	return &Config{
		tokenEndpointHttpMethods: []string{http.MethodPost},
		tokenReqValidators:       []TokenRequestValidator{},
		tokenProcessors:          []TokenProcessor{},
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
		},
		omittedScopePolicy: OmittedScopePolicyReject,
	}
}

// SetClientManager sets the client authentication manager.
func (cfg *Config) SetClientManager(mgr ClientManager) *Config {
	cfg.clientMgr = mgr
	return cfg
}

// SetUserManager sets the user authenticator used to verify the resource owner's
// credentials (username + password).
func (cfg *Config) SetUserManager(mgr UserManager) *Config {
	cfg.userMgr = mgr
	return cfg
}

// SetTokenManager sets the token generation and persistence manager.
func (cfg *Config) SetTokenManager(mgr TokenManager) *Config {
	cfg.tokenMgr = mgr
	return cfg
}

// SetSupportedClientAuthMethods overrides which client authentication methods
// are accepted at the token endpoint. Default: basic only (client_secret_basic).
func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

// SetTokenEndpointHttpMethods overrides the HTTP methods accepted at /token.
// Default: [POST].
func (cfg *Config) SetTokenEndpointHttpMethods(methods []string) *Config {
	cfg.tokenEndpointHttpMethods = methods
	return cfg
}

// SetOmittedScopePolicy sets the behavior when the client omits the scope
// parameter (RFC 6749 §3.3). Available values:
//   - OmittedScopePolicyReject (default): reject with invalid_scope.
//   - OmittedScopePolicyUseClientDefault: grant the client's full registered scope list.
func (cfg *Config) SetOmittedScopePolicy(p OmittedScopePolicy) *Config {
	cfg.omittedScopePolicy = p
	return cfg
}

// RegisterExtension adds ext to every extension slice whose interface it satisfies.
// A single object may implement both TokenRequestValidator and TokenProcessor.
func (cfg *Config) RegisterExtension(ext interface{}) *Config {
	if h, ok := ext.(TokenRequestValidator); ok {
		cfg.tokenReqValidators = append(cfg.tokenReqValidators, h)
	}

	if h, ok := ext.(TokenProcessor); ok {
		cfg.tokenProcessors = append(cfg.tokenProcessors, h)
	}

	return cfg
}

// ValidateConfig checks that all required dependencies are set and returns the
// first sentinel error encountered. Call this via Must() rather than directly.
func (cfg *Config) ValidateConfig() error {
	if utils.IsNil(cfg.clientMgr) {
		return ErrNilClientManager
	}

	if utils.IsNil(cfg.userMgr) {
		return ErrNilUserManager
	}

	if utils.IsNil(cfg.tokenMgr) {
		return ErrNilTokenManager
	}

	if len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
