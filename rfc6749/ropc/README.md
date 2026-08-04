# ropc — Resource Owner Password Credentials Grant

Package `ropc` implements the [RFC 6749 §4.3 Resource Owner Password Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3).

> **Warning:** ROPC is a legacy grant type. It requires the client to handle the user's credentials directly, which defeats many of the security benefits of OAuth 2.0. Use the Authorization Code + PKCE flow for new integrations whenever possible. ROPC is prohibited by [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700).

## How It Works

```
  +------------------------+                                              +------------------------+
  | Client                 |                                              | Authorization Server   |
  |                        |                                              | Token Endpoint         |
  | (1) Collect username   |                                              |                        |
  |     and password from  |                                              |                        |
  |     resource owner     |                                              |                        |
  |                        |--(2)---------------------------------------->|                        |
  |                        |  POST /token                                 | (3) Authenticate       |
  |                        |  Auth: Basic base64(client_id:client_secret) |     client             |
  |                        |  grant_type=password                         | (4) Authenticate user  |
  |                        |  username=alice                              | (5) Validate scope     |
  |                        |  password=s3cr3t                             | (6) Issue tokens       |
  |                        |  scope=read                                  |                        |
  |                        |<-(7)-----------------------------------------|                        |
  |                        |  access_token                                |                        |
  |                        |  + refresh_token (opt.)                      |                        |
  +------------------------+                                              +------------------------+
```

**Steps:**

1. **Client** collects `username` and `password` directly from the resource owner.
2. **Client** sends a single POST request to `/token` with `grant_type=password`, credentials, and client authentication.
3. **Server** authenticates the client application.
4. **Server** authenticates the resource owner by verifying `username` and `password`.
5. **Server** intersects the requested `scope` with the client's allowed scopes.
6. **Server** generates an access token (and a refresh token if the client has the `refresh_token` grant).
7. **Server** returns the tokens.

## Setup

```go
import "github.com/tniah/authkit/rfc6749/ropc"

cfg := ropc.NewConfig().
    SetClientManager(clientMgr).
    SetUserManager(userMgr).
    SetTokenManager(tokenMgr)

flow, err := ropc.Must(cfg)
if err != nil {
    log.Fatal(err)
}

server.RegisterGrant(flow)
```

## Required Managers

| Manager         | Interface       | Responsibility                                                      |
|-----------------|-----------------|---------------------------------------------------------------------|
| `ClientManager` | `ClientManager` | Authenticate the client application at the token endpoint.          |
| `UserManager`   | `UserManager`   | Verify the resource owner's `username` and `password`.              |
| `TokenManager`  | `TokenManager`  | Generate and persist access and refresh tokens.                     |

### `ClientManager` interface

```go
type ClientManager interface {
    Authenticate(r *http.Request, supportedMethods map[types.ClientAuthMethod]bool, endpoint string) (models.Client, error)
}
```

Typically backed by `clientauth.Manager` from `rfc6749/client_authentication`. Returns an error if the client fails to authenticate.

### `UserManager` interface

```go
type UserManager interface {
    Authenticate(username, password string, client models.Client, r *http.Request) (models.User, error)
}
```

Return `(nil, nil)` when credentials are invalid. The flow maps this to a generic `invalid_grant` response to avoid leaking whether the username exists.

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

| Interface               | Called in              | Use case                                          |
|-------------------------|------------------------|---------------------------------------------------|
| `TokenRequestValidator` | `ValidateTokenRequest` | Extra `/token` validation after built-in checks.  |
| `TokenProcessor`        | `TokenResponse`        | Add extra fields to the token response.           |

Extensions are registered via `cfg.RegisterExtension(ext)` and executed in registration order.

## Config Options

| Method                             | Default                    | Description                                               |
|------------------------------------|----------------------------|-----------------------------------------------------------|
| `SetClientManager(mgr)`            | —                          | Required. Client authentication.                          |
| `SetUserManager(mgr)`              | —                          | Required. Resource owner credential verification.         |
| `SetTokenManager(mgr)`             | —                          | Required. Token generation and persistence.               |
| `SetTokenEndpointHttpMethods(m)`   | `[POST]`                   | HTTP methods accepted at `/token`.                        |
| `SetSupportedClientAuthMethods(m)` | `client_secret_basic`      | Client authentication methods accepted at `/token`.       |
| `SetOmittedScopePolicy(p)`         | `OmittedScopePolicyReject` | Behavior when the client omits the `scope` parameter.     |
| `RegisterExtension(ext)`           | —                          | Register one or more extension hooks.                     |

### Omitted Scope Policy

Controls what happens when the client does not include a `scope` parameter (RFC 6749 §3.3):

| Policy                               | Behavior                                                    |
|--------------------------------------|-------------------------------------------------------------|
| `OmittedScopePolicyReject`           | Reject with `invalid_scope`. This is the default.           |
| `OmittedScopePolicyUseClientDefault` | Grant the client's full registered scope list.              |

```go
cfg.SetOmittedScopePolicy(ropc.OmittedScopePolicyUseClientDefault)
```

## Validation Rules

- HTTP method must be POST (configurable).
- `grant_type` must be `password`.
- `username` and `password` must be present in the request.
- Client must authenticate successfully using a supported method.
- Client must have `grant_type=password` explicitly registered; otherwise `unauthorized_client` is returned.
- When `scope` is present, it is intersected with the client's allowed scopes. If the intersection is empty, `invalid_scope` is returned.
- When `scope` is absent, behavior is determined by `OmittedScopePolicy` (default: reject with `invalid_scope`).
- If `UserManager.Authenticate` returns `nil`, `invalid_grant` is returned with a generic message.
- A refresh token is included only if the client has the `refresh_token` grant type registered.

## Security Notes

- Username/password are transmitted in plaintext in the POST body — TLS is mandatory.
- A generic `"Username or password is incorrect"` message is returned on credential failure to avoid user enumeration.
- Prefer the Authorization Code + PKCE flow for all new integrations. ROPC should only be used for migrating legacy systems where other flows are not feasible.
