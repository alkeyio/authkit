# rfc6750 — Bearer Token Generator

Package `rfc6750` implements opaque Bearer token generation as described in [RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750).

It provides `BearerTokenGenerator`, which is the default `TokenManager` implementation used by grant flows in this library.

## Components

| Type                          | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| `BearerTokenGenerator`        | Composes an access token generator and an optional refresh token generator. |
| `OpaqueAccessTokenGenerator`  | Generates a cryptographically random opaque access token string.            |
| `OpaqueRefreshTokenGenerator` | Generates a cryptographically random opaque refresh token string.           |

## Defaults

| Parameter              | Default  |
|------------------------|----------|
| Token length           | 48 chars |
| Access token expiry    | 60 min   |
| Refresh token expiry   | 24 h     |
| Token charset          | `[A-Za-z0-9]` + special chars (crypto/rand) |

## Usage

### Basic setup (opaque tokens, default options)

```go
gen := rfc6750.NewBearerTokenGenerator()
```

### Validated setup (fail fast at startup)

```go
gen, err := rfc6750.MustBearerTokenGenerator(nil) // nil = use defaults
```

### Custom expiry and token length

```go
atOpts := rfc6750.NewTokenGeneratorOptions().
    SetExpiresIn(30 * time.Minute).
    SetTokenLength(64)

rfOpts := rfc6750.NewTokenGeneratorOptions().
    SetExpiresIn(7 * 24 * time.Hour)

opts := rfc6750.NewBearerTokenGeneratorOptions().
    SetAccessTokenGenerator(rfc6750.NewOpaqueAccessTokenGenerator(atOpts)).
    SetRefreshTokenGenerator(rfc6750.NewOpaqueRefreshTokenGenerator(rfOpts))

gen := rfc6750.NewBearerTokenGenerator(opts)
```

### Dynamic expiry per client or grant type

```go
atOpts := rfc6750.NewTokenGeneratorOptions().
    SetExpiresInGenerator(func(ctx context.Context, grantType string, client models.Client) time.Duration {
        if grantType == "client_credentials" {
            return 15 * time.Minute
        }
        return 60 * time.Minute
    })

opts := rfc6750.NewBearerTokenGeneratorOptions().
    SetAccessTokenGenerator(rfc6750.NewOpaqueAccessTokenGenerator(atOpts))

gen := rfc6750.NewBearerTokenGenerator(opts)
```

### Custom token generator

```go
atOpts := rfc6750.NewTokenGeneratorOptions().
    SetRandStringGenerator(func(ctx context.Context, grantType string, client models.Client) (string, error) {
        // e.g. prefixed token: "at_<random>"
        s, err := generateMyToken()
        return "at_" + s, err
    })
```

## Options

### `TokenGeneratorOptions`

Controls the behavior of `OpaqueAccessTokenGenerator` and `OpaqueRefreshTokenGenerator`.

| Method                    | Default     | Description                                                             |
|---------------------------|-------------|-------------------------------------------------------------------------|
| `SetTokenLength(n)`       | `48`        | Length of the generated token string.                                   |
| `SetExpiresIn(d)`         | `60m` / `24h` | Static token lifetime. Ignored when `SetExpiresInGenerator` is set.   |
| `SetExpiresInGenerator(fn)` | `nil`     | Dynamic expiry hook. Receives context, grant type, and client.          |
| `SetRandStringGenerator(fn)` | `nil`   | Custom token generation hook. Replaces the built-in crypto/rand logic.  |

### `BearerTokenGeneratorOptions`

Composes the two generators used by `BearerTokenGenerator`.

| Method                          | Default                          | Description                       |
|---------------------------------|----------------------------------|-----------------------------------|
| `SetAccessTokenGenerator(gen)`  | `OpaqueAccessTokenGenerator`     | Override the access token issuer. |
| `SetRefreshTokenGenerator(gen)` | `OpaqueRefreshTokenGenerator`    | Override the refresh token issuer.|

## Integration with grant flows

Grant flows accept a `TokenManager`. Pass `BearerTokenGenerator` as the token manager when configuring a flow:

```go
gen := rfc6750.NewBearerTokenGenerator()

cfg := authorizationcode.NewConfig().
    SetTokenManager(gen).
    // ...other options
```

The flow calls `gen.Generate(token, request, includeRefreshToken)`. A refresh token is only issued when `includeRefreshToken` is `true` (i.e. the client has the `refresh_token` grant type registered).
