package authorizationcode

import (
	"errors"
	"net/http"

	"github.com/alkeyio/authkit/types"
	"github.com/alkeyio/authkit/utils"
)

// Sentinel errors returned by ValidateConfig when a required dependency is missing.
var (
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilUserManager         = errors.New("user manager is nil")
	ErrNilAuthCodeManager     = errors.New("auth code manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("client auth methods are empty")
)

// OmittedScopePolicy controls how the authorization endpoint behaves when the
// client does not include a scope parameter in the request (RFC 6749 §3.3).
type OmittedScopePolicy int

const (
	// OmittedScopePolicyReject rejects the request with invalid_scope when
	// the scope parameter is absent. This is the default.
	OmittedScopePolicyReject OmittedScopePolicy = iota

	// OmittedScopePolicyUseClientDefault grants the client's full registered
	// scope list when the scope parameter is absent.
	OmittedScopePolicyUseClientDefault
)

// Config holds all dependencies and extension hooks for the Authorization Code flow.
// Use NewConfig() to get a config with sensible defaults, then chain Set*/RegisterExtension
// calls before passing to Must() or New().
type Config struct {
	clientMgr   ClientManager
	userMgr     UserManager
	authCodeMgr AuthCodeManager
	tokenMgr    TokenManager

	authEndpointHttpMethods  []string
	tokenEndpointHttpMethods []string

	// Extension slices are executed in registration order. A single object may
	// implement multiple extension interfaces and will be appended to each
	// applicable slice (e.g. PKCE registers as both AuthCodeProcessor and
	// TokenRequestValidator).
	authReqValidators    []AuthorizationRequestValidator
	consentReqValidators []ConsentRequestValidator
	authCodeProcessors   []AuthCodeProcessor
	tokenReqValidators   []TokenRequestValidator
	tokenProcessors      []TokenProcessor

	// supportedClientAuthMethods controls which authentication methods are
	// accepted at the token endpoint (basic, post, none).
	supportedClientAuthMethods map[types.ClientAuthMethod]bool

	// omittedScopePolicy controls the behavior when the client omits the scope
	// parameter at /authorize (RFC 6749 §3.3). Default: OmittedScopePolicyReject.
	omittedScopePolicy OmittedScopePolicy
}

// NewConfig returns a Config with secure defaults:
//   - Accepts GET on /authorize, POST on /token.
//   - Supports basic and none client authentication methods.
//   - Omitted scope: reject with invalid_scope (OmittedScopePolicyReject).
func NewConfig() *Config {
	return &Config{
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
			types.ClientNoneAuthentication:  true,
		},
		authEndpointHttpMethods:  []string{http.MethodGet},
		tokenEndpointHttpMethods: []string{http.MethodPost},
		authReqValidators:        []AuthorizationRequestValidator{},
		consentReqValidators:     []ConsentRequestValidator{},
		authCodeProcessors:       []AuthCodeProcessor{},
		tokenReqValidators:       []TokenRequestValidator{},
		tokenProcessors:          []TokenProcessor{},
		omittedScopePolicy:       OmittedScopePolicyReject,
	}
}

// SetClientManager sets the client lookup and authentication manager.
func (cfg *Config) SetClientManager(mgr ClientManager) *Config {
	cfg.clientMgr = mgr
	return cfg
}

// SetUserManager sets the user resolver used to look up the resource owner
// associated with an authorization code during token exchange.
func (cfg *Config) SetUserManager(mgr UserManager) *Config {
	cfg.userMgr = mgr
	return cfg
}

// SetAuthCodeManager sets the authorization code lifecycle manager.
func (cfg *Config) SetAuthCodeManager(mgr AuthCodeManager) *Config {
	cfg.authCodeMgr = mgr
	return cfg
}

// SetTokenManager sets the token generation and persistence manager.
func (cfg *Config) SetTokenManager(mgr TokenManager) *Config {
	cfg.tokenMgr = mgr
	return cfg
}

// SetAuthEndpointHttpMethods overrides the HTTP methods accepted at /authorize.
// Default: [GET].
func (cfg *Config) SetAuthEndpointHttpMethods(methods []string) *Config {
	cfg.authEndpointHttpMethods = methods
	return cfg
}

// SetTokenEndpointHttpMethods overrides the HTTP methods accepted at /token.
// Default: [POST].
func (cfg *Config) SetTokenEndpointHttpMethods(methods []string) *Config {
	cfg.tokenEndpointHttpMethods = methods
	return cfg
}

// RegisterExtension adds ext to every extension slice whose interface it satisfies.
// Call this once per extension object; it will automatically register for all
// applicable hooks (e.g. a PKCE object implements both AuthCodeProcessor and
// TokenRequestValidator, so it is added to both slices in one call).
func (cfg *Config) RegisterExtension(ext interface{}) *Config {
	if h, ok := ext.(AuthorizationRequestValidator); ok {
		cfg.authReqValidators = append(cfg.authReqValidators, h)
	}

	if h, ok := ext.(ConsentRequestValidator); ok {
		cfg.consentReqValidators = append(cfg.consentReqValidators, h)
	}

	if h, ok := ext.(AuthCodeProcessor); ok {
		cfg.authCodeProcessors = append(cfg.authCodeProcessors, h)
	}

	if h, ok := ext.(TokenRequestValidator); ok {
		cfg.tokenReqValidators = append(cfg.tokenReqValidators, h)
	}

	if h, ok := ext.(TokenProcessor); ok {
		cfg.tokenProcessors = append(cfg.tokenProcessors, h)
	}

	return cfg
}

// SetOmittedScopePolicy sets the behavior when the client omits the scope
// parameter at /authorize (RFC 6749 §3.3). Available values:
//   - OmittedScopePolicyReject (default): reject with invalid_scope.
//   - OmittedScopePolicyUseClientDefault: grant the client's full registered scope list.
func (cfg *Config) SetOmittedScopePolicy(p OmittedScopePolicy) *Config {
	cfg.omittedScopePolicy = p
	return cfg
}

// SetSupportedClientAuthMethods overrides which client authentication methods
// are accepted at the token endpoint. Default: basic and none.
func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
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

	if utils.IsNil(cfg.authCodeMgr) {
		return ErrNilAuthCodeManager
	}

	if utils.IsNil(cfg.tokenMgr) {
		return ErrNilTokenManager
	}

	if len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
