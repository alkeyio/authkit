# rfc7662 — Token Introspection

Package `rfc7662` implements [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662).

Token Introspection allows a resource server or client to query the authorization server to determine the active state and metadata of a token without having to verify the token signature itself.

## How It Works

```
  +------------------------+                                           +------------------------+
  | Resource Server        |                                           | Authorization Server   |
  | or Client              |                                           | Introspection Endpoint |
  |                        |                                           |                        |
  | Received a token,      |                                           |                        |
  | need to verify it      |                                           |                        |
  |                        |--(1) POST /introspect ------------------->|                        |
  |                        |  [Header]                                 | (2) Authenticate       |
  |                        |  Auth: Basic                              |     caller             |
  |                        |  base64(client_id:secret)                 | (3) Look up token      |
  |                        |  [Body]                                   | (4) Check expiry       |
  |                        |  token=<token_value>                      | (5) Check permission   |
  |                        |  token_type_hint=access_token (optional)  | (6) Build payload      |
  |                        |<-(2) JSON response -----------------------|                        |
  |                        |  { "active": true,                        |                        |
  |                        |    "sub": "alice",                        |                        |
  |                        |    "scope": "read",                       |                        |
  |                        |    "exp": 1234567890 }                    |                        |
  +------------------------+                                           +------------------------+
```

**Steps:**

1. **Caller** sends a POST request to `/introspect` with the token to inspect, authenticated via `client_secret_basic`.
2. **Server** authenticates the calling client.
3. **Server** looks up the token via `TokenManager.QueryByToken`, optionally using `token_type_hint` to narrow the search.
4. **Server** checks whether the token is expired.
5. **Server** calls `ClientManager.CheckPermission` to verify the caller is allowed to inspect this token.
6. **Server** returns a JSON payload. If the token is not found or expired, `{ "active": false }` is returned.

## Setup

```go
import "github.com/alkeyio/authkit/rfc7662"

cfg := rfc7662.NewConfig().
    SetClientManager(clientMgr).
    SetTokenManager(tokenMgr)

flow, err := rfc7662.MustTokenIntrospectionFlow(cfg)
if err != nil {
    log.Fatal(err)
}

server.RegisterEndpoint(flow)
```

The flow is registered as an endpoint (not a grant), so the server dispatches to it via `EndpointResponse` when the endpoint name matches.

## Required Managers

| Manager         | Interface       | Responsibility                                              |
|-----------------|-----------------|-------------------------------------------------------------|
| `ClientManager` | `ClientManager` | Authenticate the client and check permissions.              |
| `TokenManager`  | `TokenManager`  | Look up a token by value and build the introspection payload.|

### `ClientManager` interface

```go
type ClientManager interface {
    Authenticate(r *http.Request, authMethods map[types.ClientAuthMethod]bool, endpointName string) (models.Client, error)
    CheckPermission(client models.Client, token models.Token, r *http.Request) bool
}
```

`CheckPermission` is always called for every introspection request. Return `true` to allow, `false` to reject with `access_denied`. To allow any authenticated client unconditionally, always return `true`.

### `TokenManager` interface

```go
type TokenManager interface {
    QueryByToken(ctx context.Context, token string, hint types.TokenTypeHint) (models.Token, error)
    Inspect(client models.Client, token models.Token) map[string]interface{}
}
```

`Inspect` builds the JSON payload returned to the caller. The `active` field is set by the flow automatically — do not include it in the map returned by `Inspect`.

## Response Payload

A standard introspection response includes:

| Field      | Type     | Description                                        |
|------------|----------|----------------------------------------------------|
| `active`   | `bool`   | `true` if the token is valid and not expired.      |
| `sub`      | `string` | Subject (user ID) the token was issued for.        |
| `client_id`| `string` | Client the token was issued to.                    |
| `scope`    | `string` | Space-separated list of granted scopes.            |
| `exp`      | `int`    | Expiry time as Unix timestamp.                     |
| `iat`      | `int`    | Issued-at time as Unix timestamp.                  |

All fields beyond `active` are populated by `TokenManager.Inspect`. Return only the fields relevant to your deployment.

When the token is not found or has expired, the response is always:

```json
{ "active": false }
```

## Config Options

| Method                             | Default               | Description                                              |
|------------------------------------|-----------------------|----------------------------------------------------------|
| `SetClientManager(mgr)`            | —                     | Required. Client authentication and permission check.    |
| `SetTokenManager(mgr)`             | —                     | Required. Token lookup and payload builder.              |
| `SetEndpointName(name)`            | `"introspection"`     | Name used to match this endpoint in the server router.   |
| `SetSupportedClientAuthMethods(m)` | `client_secret_basic` | Client authentication methods accepted at the endpoint.  |

## Validation Rules

- HTTP method must be `POST`.
- Content-Type must be `application/x-www-form-urlencoded`.
- `token` parameter must be present and non-empty.
- `token_type_hint` is optional and passed through as-is to `TokenManager.QueryByToken`. Unknown values are silently ignored per RFC 7662 §2.1.
- Calling client must authenticate successfully.
- If `CheckPermission` returns `false`, the request is rejected with `access_denied`.

## Security Notes

- Only authenticated clients can call the introspection endpoint. Never expose it publicly without authentication.
- A missing or expired token always returns `{ "active": false }` — no error is returned, per RFC 7662 §2.2.
- Use `CheckPermission` to restrict which clients can inspect which tokens (e.g. a resource server should only be able to inspect tokens issued to its own audience).
