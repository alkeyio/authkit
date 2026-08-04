# code_generator — Authorization Code Generator

Package `codegen` generates authorization codes for the [RFC 6749 §4.1.2 Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2).

`Generator` is the default `AuthCodeManager.Generate` implementation used by the Authorization Code flow. It populates an `AuthorizationCode` model with all required fields derived from the authorization request.

## Defaults

| Parameter       | Default    | Notes                                                              |
|-----------------|------------|--------------------------------------------------------------------|
| Code length     | 48 chars   | Alphanumeric (`[A-Za-z0-9]`), ≈285 bits of entropy via crypto/rand. |
| Code expiry     | 5 min      | RFC 6749 §4.1.2 recommends a maximum of 10 minutes.               |

## Usage

### Basic setup (secure defaults)

```go
gen := codegen.New()
```

### Custom expiry and code length

```go
opts := codegen.NewOptions().
    SetCodeLength(64).
    SetExpiresIn(3 * time.Minute)

gen := codegen.New(opts)
```

### Dynamic expiry per client

```go
opts := codegen.NewOptions().
    SetExpiresInGenerator(func(gt types.GrantType, client models.Client) time.Duration {
        if client.IsTrusted() {
            return 10 * time.Minute
        }
        return 2 * time.Minute
    })

gen := codegen.New(opts)
```

### Custom code generator

```go
opts := codegen.NewOptions().
    SetRandStringGenerator(func(gt types.GrantType, client models.Client) (string, error) {
        return myTokenMint(client.GetClientID())
    })
```

### Attaching extra data to the code

Use `SetExtraDataGenerator` to store arbitrary metadata alongside the authorization code (e.g. a session ID, nonce, or any data an extension needs to retrieve at token exchange time).

```go
opts := codegen.NewOptions().
    SetExtraDataGenerator(func(r *requests.AuthorizationRequest) (map[string]interface{}, error) {
        return map[string]interface{}{
            "session_id": r.Request.Header.Get("X-Session-ID"),
        }, nil
    })
```

The map is stored via `AuthorizationCode.SetExtraData` and can be read back in extension hooks during token exchange.

## Options

| Method                      | Default   | Description                                                                  |
|-----------------------------|-----------|------------------------------------------------------------------------------|
| `SetCodeLength(n)`          | `48`      | Length of the generated code string.                                         |
| `SetExpiresIn(d)`           | `5m`      | Static code lifetime. Ignored when `SetExpiresInGenerator` is set.           |
| `SetExpiresInGenerator(fn)` | `nil`     | Dynamic expiry hook. Takes precedence over `SetExpiresIn` when set.          |
| `SetRandStringGenerator(fn)`| `nil`     | Custom code generation hook. Replaces the built-in crypto/rand logic.        |
| `SetExtraDataGenerator(fn)` | `nil`     | Hook for attaching extra metadata to the authorization code.                 |

## Fields populated by `Generate`

| Field           | Source                                    |
|-----------------|-------------------------------------------|
| `code`          | Random string (crypto/rand or custom hook)|
| `client_id`     | `r.Client.GetClientID()`                  |
| `user_id`       | `r.User.GetUserID()`                      |
| `redirect_uri`  | `r.RedirectURI`                           |
| `response_type` | `r.ResponseType`                          |
| `scopes`        | `r.Scopes`                                |
| `state`         | `r.State`                                 |
| `auth_time`     | `time.Now().UTC()`                        |
| `expires_in`    | From options or `ExpiresInGenerator`      |
| `extra_data`    | From `ExtraDataGenerator` (if set)        |
