package types

const (
	// ScopeOpenID is the scope value required for OpenID Connect requests.
	ScopeOpenID Scope = "openid"

	// GrantTypeAuthorizationCode is the authorization code grant (RFC 6749 §4.1).
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeClientCredentials is the client credentials grant (RFC 6749 §4.4).
	GrantTypeClientCredentials GrantType = "client_credentials"
	// GrantTypeROPC is the resource owner password credentials grant (RFC 6749 §4.3).
	GrantTypeROPC GrantType = "password"
	// GrantTypeRefreshToken is the refresh token grant (RFC 6749 §6).
	GrantTypeRefreshToken GrantType = "refresh_token"

	// ResponseTypeCode is the authorization code response type (RFC 6749 §3.1.1).
	ResponseTypeCode ResponseType = "code"
	// ResponseTypeToken is the implicit grant response type (RFC 6749 §3.1.1).
	ResponseTypeToken ResponseType = "token"

	// DisplayPage requests a full-page authentication UI.
	DisplayPage Display = "page"
	// DisplayPopup requests a pop-up window authentication UI.
	DisplayPopup Display = "popup"
	// DisplayTouch requests a touch-optimised authentication UI.
	DisplayTouch Display = "touch"
	// DisplayWap requests a WAP-compatible authentication UI.
	DisplayWap Display = "wap"

	// PromptNone instructs the server to return an error if any interaction is needed.
	PromptNone Prompt = "none"
	// PromptLogin instructs the server to re-authenticate the end-user.
	PromptLogin Prompt = "login"
	// PromptConsent instructs the server to request consent from the end-user.
	PromptConsent Prompt = "consent"
	// PromptSelectAccount instructs the server to present an account selector.
	PromptSelectAccount Prompt = "select_account"

	// CodeChallengeMethodPlain is the plain PKCE challenge method. S256 is strongly preferred.
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	// CodeChallengeMethodS256 is the S256 PKCE challenge method (SHA-256 hash of the verifier).
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"

	// TokenTypeHintAccessToken hints that the submitted token is an access token.
	TokenTypeHintAccessToken TokenTypeHint = "access_token"
	// TokenTypeHintRefreshToken hints that the submitted token is a refresh token.
	TokenTypeHintRefreshToken TokenTypeHint = "refresh_token"

	// ClientBasicAuthentication is the client_secret_basic authentication method (RFC 6749 §2.3.1).
	ClientBasicAuthentication ClientAuthMethod = "client_secret_basic"
	// ClientPostAuthentication is the client_secret_post authentication method.
	ClientPostAuthentication ClientAuthMethod = "client_secret_post"
	// ClientNoneAuthentication is the "none" authentication method used by public clients.
	ClientNoneAuthentication ClientAuthMethod = "none"

	// ContentTypeJSON is the application/json content type with UTF-8 charset.
	ContentTypeJSON ContentType = "application/json;charset=UTF-8"
	// ContentTypeXWWWFormUrlencoded is the application/x-www-form-urlencoded content type.
	ContentTypeXWWWFormUrlencoded ContentType = "application/x-www-form-urlencoded"
)
