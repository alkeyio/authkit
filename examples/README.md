# Examples

Runnable examples demonstrating OAuth 2.0 and related specifications built with
[authkit](https://github.com/alkeyio/authkit).

## Available examples

| Example | RFC | Type | Description |
|---------|-----|------|-------------|
| [`rfc6749/authorization_code`](rfc6749/authorization_code/) | [RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1) | Playground | Authorization Code Grant |
| [`rfc6749/ropc`](rfc6749/ropc/) | [RFC 6749 §4.3](https://www.rfc-editor.org/rfc/rfc6749#section-4.3) | Playground | Resource Owner Password Credentials |
| [`rfc6749/client_credentials`](rfc6749/client_credentials/) | [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) | Playground | Client Credentials Grant |
| [`rfc7636`](rfc7636/) | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | Playground | Authorization Code + PKCE |
| [`rfc7662`](rfc7662/) | [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | Playground | Token Introspection |
| [`rfc9068`](rfc9068/) | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | Playground | JWT Access Tokens |

## Running

Each example is a self-contained Go program. Run from the repository root:

```bash
# Authorization Code Grant
go run ./examples/rfc6749/authorization_code

# Resource Owner Password Credentials
go run ./examples/rfc6749/ropc

# Client Credentials Grant
go run ./examples/rfc6749/client_credentials

# Authorization Code + PKCE
go run ./examples/rfc7636

# Token Introspection
go run ./examples/rfc7662

# JWT Access Tokens
go run ./examples/rfc9068
```

Refer to each example's own `README.md` for specific instructions, endpoints, and pre-seeded data.

### Environment variables

HTTP server examples share the same environment variables:

| Variable         | Default   | Description                    |
|------------------|-----------|--------------------------------|
| `SERVER_PORT`    | `9090`    | TCP port the server listens on |
| `SERVER_ADDRESS` | `0.0.0.0` | IP address to bind to          |

```bash
SERVER_PORT=8080 go run ./examples/rfc6749/ropc
```

## Shared packages

The `examples/` directory contains shared helpers used across examples:

| Package       | Description                                                         |
|---------------|---------------------------------------------------------------------|
| `assets/`     | Embedded static files (CSS, fonts) served at `/static/`             |
| `config/`     | Reads `SERVER_PORT` / `SERVER_ADDRESS` environment variables        |
| `manager/`    | In-memory implementations of `ClientManager`, `TokenManager`, etc. |
| `middleware/` | HTTP access log middleware                                          |
