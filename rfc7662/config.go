package rfc7662

import (
	"errors"

	"github.com/alkeyio/authkit/types"
	"github.com/alkeyio/authkit/utils"
)

// EndpointNameTokenIntrospection is the default endpoint name used to register
// the introspection handler with the server.
const EndpointNameTokenIntrospection = "introspection"

var (
	ErrEmptyEndpointName      = errors.New("endpoint name is empty")
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("supported client auth methods are empty")
)

// Config holds all settings for TokenIntrospectionFlow. Use NewConfig to obtain
// a value with secure defaults, then chain Set* calls to configure managers.
type Config struct {
	endpointName               string
	clientManager              ClientManager
	tokenManager               TokenManager
	supportedClientAuthMethods map[types.ClientAuthMethod]bool
}

// NewConfig returns a Config with EndpointNameTokenIntrospection as the endpoint
// name and client_secret_basic as the default client authentication method.
func NewConfig() *Config {
	return &Config{
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
		},
		endpointName: EndpointNameTokenIntrospection,
	}
}

// SetEndpointName overrides the endpoint name used by CheckEndpoint. Defaults
// to EndpointNameTokenIntrospection ("introspection").
func (cfg *Config) SetEndpointName(name string) *Config {
	cfg.endpointName = name
	return cfg
}

// SetClientManager registers the ClientManager used to authenticate the caller
// and check per-token access permissions.
func (cfg *Config) SetClientManager(mgr ClientManager) *Config {
	cfg.clientManager = mgr
	return cfg
}

// SetTokenManager registers the TokenManager used to look up tokens and build
// the introspection response payload.
func (cfg *Config) SetTokenManager(mgr TokenManager) *Config {
	cfg.tokenManager = mgr
	return cfg
}

// SetSupportedClientAuthMethods overrides the set of client authentication
// methods accepted at the introspection endpoint.
func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

// ValidateConfig returns an error if any required configuration is missing.
// Call this via MustTokenIntrospectionFlow rather than directly.
func (cfg *Config) ValidateConfig() error {
	if cfg.endpointName == "" {
		return ErrEmptyEndpointName
	}

	if utils.IsNil(cfg.clientManager) {
		return ErrNilClientManager
	}

	if utils.IsNil(cfg.tokenManager) {
		return ErrNilTokenManager
	}

	if len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
