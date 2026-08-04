# client_credentials — Client Credentials Grant

Package `clientcredentials` implements the [RFC 6749 §4.4 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4).

## How It Works

```
  +------------------------+                                              +------------------------+
  | Client                 |                                              | Authorization Server   |
  | (Confidential)         |                                              | Token Endpoint         |
  |                        |--(1)---------------------------------------->|                        |
  |                        |  POST /token                                 | (2) Authenticate client|
  |                        |  Auth: Basic base64(client_id:client_secret) | (3) Validate scope     |
  |                        |  grant_type=client_credentials               | (4) Issue access token |
  |                        |  scope=read write                            |                        |
  |                        |<-(5)-----------------------------------------|                        |
  |                        |  access_token                                |                        |
  |                        |  (no refresh_token)                          |                        |
  +------------------------+                                              +------------------------+
```

**Steps:**

1. **Client** sends a POST request to `/token` with `grant_type=client_credentials` and its own credentials via client authentication (e.g. HTTP Basic).
2. **Server** authenticates the client application. Public clients are rejected — only confidential clients may use this grant.
3. **Server** intersects the requested `scope` with the client's allowed scopes.
4. **Server** generates an access token.
5. **Server** returns the access token. A refresh token is **never** included (RFC 6749 §4.4.3).

## Setup

```go
import "github.com/alkeyio/authkit/rfc6749/client_credentials"

cfg := clientcredentials.NewConfig().
    SetClientManager(clientMgr).
    SetTokenManager(tokenMgr)

flow, err := clientcredentials.Must(cfg)
if err != nil {
    log.Fatal(err)
}

server.RegisterGrant(flow)
```

## Required Managers

| Manager         | Interface       | Responsibility                                                      |
|-----------------|-----------------|---------------------------------------------------------------------|
| `ClientManager` | `ClientManager` | Authenticate the client application at the token endpoint.          |
| `TokenManager`  | `TokenManager`  | Generate and persist access tokens.                                 |

### `ClientManager` interface

```go
type ClientManager interface {
    Authenticate(r *http.Request, supportedMethods map[types.ClientAuthMethod]bool, endpoint string) (models.Client, error)
}
```

Typically backed by `clientauth.Manager` from `rfc6749/client_authentication`.

### `TokenManager` interface

```go
type TokenManager interface {
    New() models.Token
    Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error
    Save(ctx context.Context, token models.Token) error
}
```

`includeRefreshToken` is always `false` for this grant. Typically backed by `rfc6750.BearerTokenGenerator` or `rfc9068.JWTAccessTokenGenerator`.

## Extension System

| Interface               | Called in              | Use case                                         |
|-------------------------|------------------------|--------------------------------------------------|
| `TokenRequestValidator` | `ValidateTokenRequest` | Extra `/token` validation after built-in checks. |
| `TokenProcessor`        | `TokenResponse`        | Add extra fields to the token response.          |

Extensions are registered via `cfg.RegisterExtension(ext)` and executed in registration order. A single object may implement both interfaces.

```go
cfg.RegisterExtension(myExt) // implements TokenRequestValidator and/or TokenProcessor
```

## Config Options

| Method                             | Default                 | Description                                                    |
|------------------------------------|-------------------------|----------------------------------------------------------------|
| `SetClientManager(mgr)`            | —                       | Required. Client authentication.                               |
| `SetTokenManager(mgr)`             | —                       | Required. Token generation and persistence.                    |
| `SetTokenEndpointHttpMethods(m)`   | `[POST]`                | HTTP methods accepted at `/token`.                             |
| `SetSupportedClientAuthMethods(m)` | `client_secret_basic`   | Client authentication methods accepted at `/token`.            |
| `SetOmittedScopePolicy(p)`         | `OmittedScopePolicyReject` | Behavior when the client omits the `scope` parameter.       |
| `RegisterExtension(ext)`           | —                       | Register one or more extension hooks.                          |

### Omitted Scope Policy

Controls what happens when the client does not include a `scope` parameter (RFC 6749 §3.3):

| Policy                          | Behavior                                                    |
|---------------------------------|-------------------------------------------------------------|
| `OmittedScopePolicyReject`      | Reject with `invalid_scope`. This is the default.          |
| `OmittedScopePolicyUseClientDefault` | Grant the client's full registered scope list.        |

```go
cfg.SetOmittedScopePolicy(clientcredentials.OmittedScopePolicyUseClientDefault)
```

## Validation Rules

- HTTP method must be POST (configurable).
- `grant_type` must be `client_credentials`.
- Client must authenticate successfully using a supported method.
- Client must be confidential — public clients (none auth method) are rejected with `invalid_client`.
- Client must have `grant_type=client_credentials` explicitly registered; otherwise `unauthorized_client` is returned.
- When `scope` is present, it is intersected with the client's allowed scopes. If the intersection is empty, `invalid_scope` is returned.
- When `scope` is absent, behavior is determined by `OmittedScopePolicy` (default: reject).

## Security Notes

- Only confidential clients that can securely hold a secret are permitted. Public clients are explicitly rejected per RFC 6749 §4.4.
- No refresh token is ever issued. The client can re-authenticate using its credentials at any time.
- TLS is mandatory — client credentials are transmitted in the Authorization header.
