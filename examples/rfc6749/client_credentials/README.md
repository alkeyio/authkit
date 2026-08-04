# Client Credentials — Example

An interactive playground demonstrating the OAuth 2.0 Client Credentials grant
([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)) built with
[authkit](https://github.com/alkeyio/authkit).

![Client Credentials Playground](docs/screenshot.png)

## Running

```bash
go run ./examples/rfc6749/client_credentials
```

Then open [http://localhost:9090](http://localhost:9090) in your browser.

### Environment variables

| Variable         | Default   | Description                    |
|------------------|-----------|--------------------------------|
| `SERVER_PORT`    | `9090`    | TCP port the server listens on |
| `SERVER_ADDRESS` | `0.0.0.0` | IP address to bind to          |

```bash
SERVER_PORT=8080 go run ./examples/rfc6749/client_credentials
```

## Endpoints

| Method | Path     | Description    |
|--------|----------|----------------|
| `GET`  | `/`      | Playground UI  |
| `POST` | `/token` | Token endpoint |

## Pre-seeded data

### Client

| Field                        | Value                  |
|------------------------------|------------------------|
| `client_id`                  | `cc-demo-client`       |
| `client_secret`              | `cc-demo-secret`       |
| `token_endpoint_auth_method` | `client_secret_basic`  |
| `grant_types`                | `client_credentials`   |
| `scopes`                     | `read`, `write`        |

## Flow

```
1. POST /token  →  Token request (grant_type=client_credentials + client auth + scope)
2. HTTP 200     →  Server returns access token (no refresh_token)
```

The playground lets you edit the client credentials, switch the auth method, and toggle
scopes before stepping through the flow — displaying the real HTTP request and response
at each step.

## Playground features

- **Editable fields**: `client_id`, `client_secret`
- **Auth method selector**: switch between `client_secret_basic` and `client_secret_post`
- **Scope toggle**: click individual scopes to include or exclude them from the request
- **Live preview**: the HTTP request display updates as you type

## Code structure

```
client_credentials/
├── main.go        # Entry point: reads config, starts HTTP server
├── server.go      # SetupServer: wires grant, registers routes
├── index.html     # Playground UI shell
└── static/
    └── app.js     # Flow logic and rendering
```

Shared static assets (fonts, CSS) are served from `examples/assets/`.
