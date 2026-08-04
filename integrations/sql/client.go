// Package sql provides reference implementations of the authkit model
// interfaces backed by a SQL-friendly struct layout. These types are intended
// as a starting point; copy and adapt them to match your own database schema.
package sql

import (
	"crypto/subtle"
	"time"

	"github.com/alkeyio/authkit/models"
	"github.com/alkeyio/authkit/types"
)

// Compile-time check that *Client implements models.Client.
var _ models.Client = (*Client)(nil)

type Client struct {
	ClientName              string    `json:"client_name"`
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret"`
	RedirectURIs            []string  `json:"redirect_uris"`
	ResponseTypes           []string  `json:"response_types"`
	GrantTypes              []string  `json:"grant_types"`
	Scopes                  []string  `json:"scopes"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	ClientURI               string    `json:"client_uri"`
	LogoURI                 string    `json:"logo_uri"`
	Contacts                []string  `json:"contacts"`
	TosURI                  string    `json:"tos_uri"`
	PolicyURI               string    `json:"policy_uri"`
	JWKsURI                 string    `json:"jwks_uri"`
	SoftwareID              string    `json:"software_id"`
	SoftwareVersion         string    `json:"software_version"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

func (c *Client) GetClientName() string {
	return c.ClientName
}

func (c *Client) SetClientName(name string) {
	c.ClientName = name
}

func (c *Client) GetClientID() string {
	return c.ClientID
}

func (c *Client) SetClientID(id string) {
	c.ClientID = id
}

func (c *Client) GetClientSecret() string {
	return c.ClientSecret
}

func (c *Client) SetClientSecret(secret string) {
	c.ClientSecret = secret
}

func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c *Client) GetResponseTypes() types.ResponseTypes {
	return types.NewResponseTypes(c.ResponseTypes)
}

func (c *Client) SetResponseTypes(resTypes types.ResponseTypes) {
	c.ResponseTypes = resTypes.String()
}

func (c *Client) GetGrantTypes() types.GrantTypes {
	return types.NewGrantTypes(c.GrantTypes)
}

func (c *Client) SetGrantTypes(gTypes types.GrantTypes) {
	c.GrantTypes = gTypes.String()
}

func (c *Client) GetScopes() types.Scopes {
	return types.NewScopes(c.Scopes)
}

func (c *Client) SetScopes(scopes types.Scopes) {
	c.Scopes = scopes.String()
}

func (c *Client) GetAllowedScopes(scopes types.Scopes) types.Scopes {
	allowed := make(map[string]bool)
	for _, s := range c.Scopes {
		allowed[s] = true
	}

	ret := make(types.Scopes, 0)
	for _, s := range scopes {
		if _, ok := allowed[s.String()]; ok {
			ret = append(ret, s)
		}
	}

	return ret
}

func (c *Client) GetTokenEndpointAuthMethod() types.ClientAuthMethod {
	return types.NewClientAuthMethod(c.TokenEndpointAuthMethod)
}

func (c *Client) SetTokenEndpointAuthMethod(m types.ClientAuthMethod) {
	c.TokenEndpointAuthMethod = m.String()
}

func (c *Client) GetDefaultRedirectURI() string {
	if len(c.RedirectURIs) == 0 {
		return ""
	}

	return c.RedirectURIs[0]
}

func (c *Client) CheckRedirectURI(redirectURI string) bool {
	for i := range c.RedirectURIs {
		if c.RedirectURIs[i] == redirectURI {
			return true
		}
	}

	return false
}

func (c *Client) CheckGrantType(gt types.GrantType) bool {
	for i := range c.GrantTypes {
		if c.GrantTypes[i] == gt.String() {
			return true
		}
	}

	return false
}

func (c *Client) CheckResponseType(rt types.ResponseType) bool {
	for i := range c.ResponseTypes {
		if c.ResponseTypes[i] == rt.String() {
			return true
		}
	}

	return false
}

// CheckTokenEndpointAuthMethod reports whether method matches the client's
// configured auth method. The endpoint parameter is intentionally ignored:
// this implementation uses a single auth method for all endpoints.
func (c *Client) CheckTokenEndpointAuthMethod(method types.ClientAuthMethod, endpoint string) bool {
	return c.TokenEndpointAuthMethod == method.String()
}

func (c *Client) CheckClientSecret(secret string) bool {
	return subtle.ConstantTimeCompare([]byte(c.ClientSecret), []byte(secret)) == 1
}

func (c *Client) IsPublic() bool {
	return c.TokenEndpointAuthMethod == string(types.ClientNoneAuthentication)
}
