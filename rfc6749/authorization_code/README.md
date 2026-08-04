# authorization_code — Authorization Code Grant

Package `authorizationcode` implements the [RFC 6749 §4.1 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).

This is the recommended grant type for most applications. The client never handles the user's credentials directly — the authorization server issues a short-lived code that the client exchanges for an access token.

## How It Works

```
                                                    +----------------------------+
                                                    |      Authorization Server  |
  +----------------------------+                    | +------------------------+ |
  | Client                     |                    | |  Authorization         | |
  |                            |                    | |  Endpoint              | |
  |                            |--(1) /authorize -->| |                        | |
  |                            |    client_id       | | (2) Authenticate user  | |
  |                            |    redirect_uri    | |     validate request   | |
  |                            |    response_type   | |                        | |
  |                            |    scope, state    | | (3) Issue auth code    | |
  |                            |<--(4) code --------|  |    redirect back      | |
  |                            |       + state      | |                        | |
  |                            |                    | +------------------------+ |
  |                            |                    |                            |
  |                            |                    | +------------------------+ |
  |                            |--(5) /token ------>| |  Token Endpoint        | |
  |                            |    code            | |                        | |
  |                            |    client_id       | | (6) Validate code      | |
  |                            |    redirect_uri    | |     authenticate client| |
  |                            |<--(7) tokens ------|  |    issue tokens       | |
  +----------------------------+                    | +------------------------+ |
                                                    +----------------------------+
```

**Steps:**

1. **Client** redirects the user-agent to `/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, and `state`.
2. **Server** authenticates the user and presents a consent screen.
3. **Server** generates a short-lived authorization code and stores it alongside the request parameters.
4. **Server** redirects the user-agent back to `redirect_uri` with the `code` and `state`.
5. **Client** exchanges the `code` for tokens by calling `/token` with `grant_type=authorization_code`.
6. **Server** validates the code, authenticates the client, verifies `redirect_uri`, and checks expiry.
7. **Server** issues an access token (and optionally a refresh token), then deletes the code to prevent reuse.

## Setup

```go
import authorizationcode "github.com/alkeyio/authkit/rfc6749/authorization_code"

cfg := authorizationcode.NewConfig().
    SetClientManager(clientMgr).
    SetAuthCodeManager(authCodeMgr).
    SetTokenManager(tokenMgr).
    SetUserManager(userMgr)

flow, err := authorizationcode.Must(cfg)
if err != nil {
    log.Fatal(err)
}

server.RegisterGrant(flow)
```

## Required Managers

| Manager           | Interface           | Responsibility                                                     |
|-------------------|---------------------|--------------------------------------------------------------------|
| `ClientManager`   | `ClientManager`     | Look up clients by `client_id`; authenticate clients at `/token`.  |
| `UserManager`     | `UserManager`       | Resolve the resource owner linked to an authorization code.        |
| `AuthCodeManager` | `AuthCodeManager`   | Generate, store, look up, and delete authorization codes.          |
| `TokenManager`    | `TokenManager`      | Generate and persist access and refresh tokens.                    |

### `ClientManager` interface

```go
type ClientManager interface {
    QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
    Authenticate(r *http.Request, authMethods map[types.ClientAuthMethod]bool, endpointName string) (models.Client, error)
}
```

Typically backed by `clientauth.Manager` from `rfc6749/client_authentication`. `QueryByClientID` is used at the `/authorize` endpoint; `Authenticate` is used at the `/token` endpoint.

### `UserManager` interface

```go
type UserManager interface {
    QueryUserByCode(ctx context.Context, code models.AuthorizationCode, r *requests.TokenRequest) (models.User, error)
}
```

Resolves the resource owner from the authorization code during token exchange. Return `(nil, nil)` when no user is found; the flow maps this to `invalid_grant`.

### `AuthCodeManager` interface

```go
type AuthCodeManager interface {
    New() models.AuthorizationCode
    Generate(authCode models.AuthorizationCode, r *requests.AuthorizationRequest) error
    Save(ctx context.Context, code models.AuthorizationCode) error
    QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
    DeleteByCode(ctx context.Context, code string) error
}
```

Typically composed with `codegen.Generator` from `rfc6749/code_generator` to implement `Generate`.

### `TokenManager` interface

```go
type TokenManager interface {
    New() models.Token
    Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error
    Save(ctx context.Context, token models.Token) error
}
```

Typically backed by `rfc6750.BearerTokenGenerator`. A refresh token is only generated when `includeRefreshToken` is `true` (i.e. the client has the `refresh_token` grant type registered).

## Extension System

Extensions are registered via `cfg.RegisterExtension(ext)`. A single object may implement multiple extension interfaces and will be registered for all applicable hooks automatically.

| Interface                       | Called in                        | Use case                                           |
|---------------------------------|----------------------------------|----------------------------------------------------|
| `AuthorizationRequestValidator` | `ValidateAuthorizationRequest`   | Extra `/authorize` validation (e.g. PKCE, OIDC).  |
| `ConsentRequestValidator`       | `ValidateConsentRequest`         | Extra consent screen validation.                   |
| `AuthCodeProcessor`             | `AuthorizationResponse`          | Attach data to the auth code (e.g. PKCE challenge).|
| `TokenRequestValidator`         | `ValidateTokenRequest`           | Extra `/token` validation (e.g. PKCE verifier).    |
| `TokenProcessor`                | `TokenResponse`                  | Add fields to the token response (e.g. `id_token`).|

Extensions are executed in registration order.

### Example: adding PKCE

```go
pkce := rfc7636.New()

cfg := authorizationcode.NewConfig().
    SetClientManager(clientMgr).
    SetAuthCodeManager(authCodeMgr).
    SetTokenManager(tokenMgr).
    SetUserManager(userMgr).
    RegisterExtension(pkce)
```

`rfc7636.ProofKeyForCodeExchangeFlow` implements `AuthorizationRequestValidator`, `AuthCodeProcessor`, and `TokenRequestValidator` — all registered in one call.

## Config Options

| Method                            | Default                    | Description                                               |
|-----------------------------------|----------------------------|-----------------------------------------------------------|
| `SetClientManager(mgr)`           | —                          | Required. Client lookup and authentication.               |
| `SetAuthCodeManager(mgr)`         | —                          | Required. Authorization code lifecycle.                   |
| `SetTokenManager(mgr)`            | —                          | Required. Token generation and persistence.               |
| `SetUserManager(mgr)`             | —                          | Required. User resolution from auth code.                 |
| `SetAuthEndpointHttpMethods(m)`   | `[GET]`                    | HTTP methods accepted at `/authorize`.                    |
| `SetTokenEndpointHttpMethods(m)`  | `[POST]`                   | HTTP methods accepted at `/token`.                        |
| `SetSupportedClientAuthMethods(m)`| `client_secret_basic`, `none` | Client authentication methods accepted at `/token`.    |
| `SetOmittedScopePolicy(p)`        | `OmittedScopePolicyReject` | Behavior when the client omits `scope` at `/authorize`.   |
| `RegisterExtension(ext)`          | —                          | Register one or more extension hooks.                     |

### Omitted Scope Policy

Controls what happens when the client does not include a `scope` parameter in the `/authorize` request (RFC 6749 §3.3):

| Policy                               | Behavior                                                    |
|--------------------------------------|-------------------------------------------------------------|
| `OmittedScopePolicyReject`           | Reject with `invalid_scope`. This is the default.           |
| `OmittedScopePolicyUseClientDefault` | Grant the client's full registered scope list.              |

```go
cfg.SetOmittedScopePolicy(authorizationcode.OmittedScopePolicyUseClientDefault)
```

## Validation Rules

### Authorization endpoint (`/authorize`)

- HTTP method must be in the configured list (default: GET).
- `client_id` must be present and match a known client.
- `redirect_uri` must be registered for the client; falls back to the client's default if omitted.
- `response_type` must be `code` and permitted for the client.
- When `scope` is present, it is intersected with the client's allowed scopes. If the intersection is empty, `invalid_scope` is returned.
- When `scope` is absent, behavior is determined by `OmittedScopePolicy` (default: reject with `invalid_scope`).
- All registered `AuthorizationRequestValidator` extensions run after the built-in checks.

### Token endpoint (`/token`)

- HTTP method must be in the configured list (default: POST).
- `grant_type` must be `authorization_code`.
- Client must authenticate successfully using a supported method.
- `code` must exist, belong to the authenticated client, and not be expired.
- `redirect_uri` must match the value stored with the code.
- All registered `TokenRequestValidator` extensions run after the built-in checks.
- The authorization code is deleted after a successful token exchange (one-time use).

## Security Notes

- The authorization code is deleted immediately after it is exchanged for a token, preventing reuse attacks.
- `redirect_uri` is verified at the token endpoint against the value stored when the code was issued, preventing open-redirect and code-injection attacks.
- Combining this flow with PKCE (`rfc7636`) is strongly recommended for public clients (native apps, single-page applications) to prevent authorization code interception attacks.
