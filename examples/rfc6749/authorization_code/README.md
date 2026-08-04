# Authorization Code Grant — Example

An interactive playground demonstrating the OAuth 2.0 Authorization Code flow
([RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)) built with
[authkit](https://github.com/alkeyio/authkit).

![Authorization Code Playground](docs/screenshot.png)

## Running

```bash
go run ./examples/rfc6749/authorization_code
```

Then open [http://localhost:9090](http://localhost:9090) in your browser.

### Environment variables

| Variable         | Default   | Description                    |
|------------------|-----------|--------------------------------|
| `SERVER_PORT`    | `9090`    | TCP port the server listens on |
| `SERVER_ADDRESS` | `0.0.0.0` | IP address to bind to          |

```bash
SERVER_PORT=8080 go run ./examples/rfc6749/authorization_code
```

## Endpoints

| Method | Path         | Description            |
|--------|--------------|------------------------|
| `GET`  | `/`          | Playground UI          |
| `GET`  | `/authorize` | Authorization endpoint |
| `POST` | `/token`     | Token endpoint         |

## Pre-seeded data

### Client

| Field                        | Value                                         |
|------------------------------|-----------------------------------------------|
| `client_id`                  | `demo-client-id`                              |
| `client_name`                | `Authorization Code Grant Demo`               |
| `token_endpoint_auth_method` | `none` (public client)                        |
| `grant_types`                | `authorization_code`                          |
| `response_types`             | `code`                                        |
| `scopes`                     | `profile`, `email`                            |
| `redirect_uris`              | `http://<SERVER_ADDRESS>:<SERVER_PORT>/callback` |

### User

| Username | Password |
|----------|----------|
| `alice`  | `secret` |

> The `/authorize` endpoint skips the login screen and authenticates as alice
> automatically, simulating an already logged-in session.

## Flow

```
1. GET /authorize  →  Authorization request
2. HTTP 302        →  Server redirects with authorization code
3. POST /token     →  Client exchanges code for tokens
4. HTTP 200        →  Server returns access token
```

Each stage displays the real HTTP request and response, including headers and body.

## Code structure

```
authorization_code/
├── main.go        # Entry point: reads config, starts HTTP server
├── server.go      # SetupServer: wires grant, registers routes
├── index.html     # Playground UI shell
└── static/
    └── app.js     # Flow logic and rendering
```

Shared static assets (fonts, CSS) are served from `examples/assets/`.
