# models

Core domain interfaces for authkit. Every grant flow and token generator works exclusively against these interfaces — your application provides the concrete implementations backed by whatever storage layer you choose (SQL, Redis, in-memory, etc.).

A reference implementation is available in [`integrations/sql`](../integrations/sql/).

## Interfaces

### `Client`

Represents an OAuth 2.0 client application (RFC 6749 §2).

| Method                                                              | Description                                                                                      |
|---------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `GetClientID() string`                                              | Returns the unique public identifier of the client.                                              |
| `GetAllowedScopes(scopes Scopes) Scopes`                            | Returns the subset of requested scopes the client is permitted to use.                           |
| `GetDefaultRedirectURI() string`                                    | Returns the default redirect URI when the authorization request omits `redirect_uri`.            |
| `CheckRedirectURI(redirectURI string) bool`                         | Reports whether `redirectURI` is registered for this client.                                     |
| `CheckGrantType(gt GrantType) bool`                                 | Reports whether this client is permitted to use the given grant type.                            |
| `CheckResponseType(rt ResponseType) bool`                           | Reports whether this client is permitted to use the given response type.                         |
| `CheckTokenEndpointAuthMethod(method ClientAuthMethod, endpoint string) bool` | Reports whether the client supports the given auth method at the specified endpoint. |
| `CheckClientSecret(secret string) bool`                             | Verifies the provided secret against the client's stored credential. Must use constant-time comparison. |
| `IsPublic() bool`                                                   | Reports whether this is a public client (RFC 6749 §2.1) — one that cannot securely store a secret. |

---

### `User`

Represents an authenticated end-user. Intentionally minimal — any user model can satisfy it without changes to the core library.

| Method                  | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `GetUserID() string`    | Returns the unique identifier of the user (used as the `sub` claim in JWT access tokens). |

---

### `Token` / `ExtendableToken`

`Token` represents an issued OAuth 2.0 access/refresh token pair.

`ExtendableToken` embeds `Token` and adds a free-form `data` map for application-specific fields.

| Method                                          | Description                                                              |
|-------------------------------------------------|--------------------------------------------------------------------------|
| `GetType() / SetType(string)`                   | Token type (e.g. `Bearer`).                                              |
| `GetAccessToken() / SetAccessToken(string)`     | Access token string.                                                     |
| `GetRefreshToken() / SetRefreshToken(string)`   | Refresh token string.                                                    |
| `GetClientID() / SetClientID(string)`           | Client identifier the token was issued to.                               |
| `GetScopes() / SetScopes(Scopes)`               | Granted scopes.                                                          |
| `GetIssuedAt() / SetIssuedAt(time.Time)`        | Issuance time.                                                           |
| `GetAccessTokenExpiresIn() / SetAccessTokenExpiresIn(time.Duration)` | Access token lifetime.                          |
| `GetRefreshTokenExpiresIn() / SetRefreshTokenExpiresIn(time.Duration)` | Refresh token lifetime.                       |
| `GetUserID() / SetUserID(string)`               | Resource owner identifier. Empty for client credentials grants.          |
| `GetJwtID() / SetJwtID(string)`                 | JWT ID (`jti`) for RFC 9068 access tokens. Empty for opaque tokens.      |
| `GetExtraData() / SetExtraData(map[string]interface{})` | *(ExtendableToken only)* Application-specific extra data.        |

---

### `AuthorizationCode` / `ExtendableAuthorizationCode`

`AuthorizationCode` represents an OAuth 2.0 authorization code issued at the `/authorize` endpoint (RFC 6749 §4.1.2).

`ExtendableAuthorizationCode` embeds `AuthorizationCode` and adds a free-form `data` map for application-specific fields.

| Method                                                              | Description                                                              |
|---------------------------------------------------------------------|--------------------------------------------------------------------------|
| `GetCode() / SetCode(string)`                                       | Authorization code string.                                               |
| `GetClientID() / SetClientID(string)`                               | Client identifier the code was issued to.                                |
| `GetUserID() / SetUserID(string)`                                   | User who authorized the request.                                         |
| `GetRedirectURI() / SetRedirectURI(string)`                         | Redirect URI from the authorization request. Must be verified again at the token endpoint. |
| `GetResponseType() / SetResponseType(ResponseType)`                 | Response type (e.g. `code`).                                             |
| `GetScopes() / SetScopes(Scopes)`                                   | Approved scopes.                                                         |
| `GetNonce() / SetNonce(string)`                                     | OIDC nonce value forwarded to the ID token.                              |
| `GetState() / SetState(string)`                                     | State parameter echoed from the authorization request.                   |
| `GetAuthTime() / SetAuthTime(time.Time)`                            | Time the user authenticated.                                             |
| `GetExpiresIn() / SetExpiresIn(time.Duration)`                      | Code lifetime (RFC 6749 §4.1.2 recommends a maximum of 10 minutes).     |
| `GetCodeChallenge() / SetCodeChallenge(string)`                     | PKCE code challenge (RFC 7636).                                          |
| `GetCodeChallengeMethod() / SetCodeChallengeMethod(CodeChallengeMethod)` | PKCE challenge method (`plain` or `S256`).                          |
| `GetExtraData() / SetExtraData(map[string]interface{})` | *(ExtendableAuthorizationCode only)* Application-specific extra data.    |

## Implementing the Interfaces

Implement only the interfaces required by the grant flows you register. A minimal authorization code setup needs all four; a client credentials setup does not need `AuthorizationCode` or `User`.

```go
type MyClient struct { ... }

func (c *MyClient) GetClientID() string                          { return c.ID }
func (c *MyClient) GetAllowedScopes(s types.Scopes) types.Scopes { ... }
// ... remaining methods
```

Use `integrations/sql` as a reference for the full implementation of each interface.
