# client_authentication — Client Authentication

Package `clientauth` implements client authentication for the OAuth 2.0 token endpoint as defined in [RFC 6749 §2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3).

It provides a `Manager` that dispatches authentication to pluggable `Handler` implementations, one per supported authentication method.

## Supported Methods

| Method                | Handler              | Credentials location                                    |
|-----------------------|----------------------|---------------------------------------------------------|
| `client_secret_basic` | `BasicAuthHandler`   | `Authorization: Basic <base64(client_id:secret)>`       |
| `client_secret_post`  | `PostAuthHandler`    | POST body: `client_id` + `client_secret`                |
| `none`                | `NoneAuthHandler`    | POST body: `client_id` only (public clients, no secret) |

## Setup

```go
store := &MyClientStore{} // implements clientauth.ClientStore

mgr := clientauth.NewManager()
mgr.Register(clientauth.NewBasicAuthHandler(store))
mgr.Register(clientauth.NewPostAuthHandler(store))
mgr.Register(clientauth.NewNoneAuthHandler(store))
```

Pass the manager as the `ClientManager` when configuring a grant flow:

```go
cfg := authorizationcode.NewConfig().
    SetClientManager(mgr).
    // ...
```

## How Authentication Works

`Manager.Authenticate` iterates over the methods permitted by the grant flow (`supportedMethods`). For each method, it calls the registered handler. The first handler that returns a valid client whose `token_endpoint_auth_method` matches the attempted method wins.

If no handler succeeds, `invalid_client` is returned. When `client_secret_basic` is among the supported methods, the response carries HTTP 401 with a `WWW-Authenticate` header as required by RFC 6749 §5.2.

## Handlers

### `BasicAuthHandler` — `client_secret_basic`

Reads credentials from the HTTP Basic Authorization header.

```go
// Simple
h := clientauth.NewBasicAuthHandler(store)

// Validated (returns error if store is nil)
h, err := clientauth.MustBasicAuthHandler(store)
```

Authentication steps:
1. Parse `Authorization: Basic <base64(client_id:client_secret)>`.
2. Look up client by `client_id`.
3. Verify `client_secret` via `client.CheckClientSecret`.

### `PostAuthHandler` — `client_secret_post`

Reads credentials from the POST form body (`Content-Type: application/x-www-form-urlencoded`).

```go
h := clientauth.NewPostAuthHandler(store)

h, err := clientauth.MustPostAuthHandler(store)
```

Authentication steps:
1. Verify method is POST and content type is `application/x-www-form-urlencoded`.
2. Read `client_id` and `client_secret` from the form body.
3. Look up client by `client_id`.
4. Verify `client_secret` via `client.CheckClientSecret`.

### `NoneAuthHandler` — `none`

For public clients that cannot hold a secret. Only `client_id` is required — no secret is transmitted or verified.

```go
h := clientauth.NewNoneAuthHandler(store)

h, err := clientauth.MustNoneAuthHandler(store)
```

Authentication steps:
1. Verify method is POST and content type is `application/x-www-form-urlencoded`.
2. Read `client_id` from the form body.
3. Look up client by `client_id`.

> Use this method together with PKCE (`rfc7636`) for public clients to prevent authorization code interception attacks.

## Implementing `ClientStore`

```go
type ClientStore interface {
    QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
}
```

Return `(nil, nil)` when the client does not exist. The handler will map it to `ErrInvalidClient`.

## Custom Handler

Register any type that implements the `Handler` interface to support additional authentication methods (e.g. `private_key_jwt`, mTLS):

```go
type Handler interface {
    Method() types.ClientAuthMethod
    Authenticate(r *http.Request) (models.Client, error)
}

mgr.Register(myCustomHandler)
```

Registering a handler for an already-registered method replaces the previous one.

## Security Notes

- All handlers return the generic `ErrInvalidClient` error on failure, regardless of which check failed, to avoid leaking whether the `client_id` exists or whether the secret was wrong.
- `BasicAuthHandler` triggers HTTP 401 with `WWW-Authenticate: Basic` when authentication fails, as required by RFC 6749 §5.2.
