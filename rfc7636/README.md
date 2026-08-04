# rfc7636 — Proof Key for Code Exchange (PKCE)

Package `rfc7636` implements [RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636).

PKCE is a security extension for the Authorization Code grant that protects against authorization code interception attacks. It is designed primarily for public clients (native apps, single-page applications) that cannot securely store a client secret, but can be applied to confidential clients as well.

## How It Works

```
                                                    +----------------------------+
                                                    |      Authorization Server  |
  +----------------------------+                    | +------------------------+ |
  | Client                     |                    | |  Authorization         | |
  |                            |                    | |  Endpoint              | |
  | (1) Generate secret:       |                    | |                        | |
  |     code_verifier (random) |                    | |                        | |
  |     code_challenge=S256(.) |                    | |                        | |
  |                            |--(2) /authorize -->| |                        | |
  |                            |    code_challenge  | | (3) Validate &         | |
  |                            |    + method=S256   | |     store challenge    | |
  |                            |<--(4) code --------|  |    + method           | |
  |                            |                    | |                        | |
  |                            |                    | +------------------------+ |
  |                            |                    |                            |
  |                            |                    | +------------------------+ |
  |                            |--(5) /token ------>| |  Token Endpoint        | |
  |                            |    code            | |                        | |
  |                            |    + code_verifier | | (6) Re-derive &        | |
  |                            |                    | |     compare challenge  | |
  |                            |<--(7) access_token-| |                        | |
  +----------------------------+                    | +------------------------+ |
                                                    +----------------------------+
```

**Steps:**

1. **Client** generates a cryptographically random `code_verifier` (43–128 unreserved characters) and derives `code_challenge = BASE64URL(SHA256(code_verifier))`.
2. **Client** sends `code_challenge` and `code_challenge_method=S256` in the `/authorize` request.
3. **Server** validates the challenge format and stores `code_challenge` + `code_challenge_method` alongside the authorization code.
4. **Server** redirects the user-agent back to `redirect_uri` with the authorization `code`.
5. **Client** sends the original `code_verifier` (never the challenge) in the `/token` request.
6. **Server** re-derives the challenge from `code_verifier` and compares it to the stored value. A mismatch means the code was intercepted by a different party.
7. **Server** issues the access token only if verification passes.

## Supported Transform Methods

| Method  | Algorithm                          | RFC 7636 | RFC 9700 |
|---------|------------------------------------|----------|----------|
| `S256`  | `BASE64URL(SHA256(code_verifier))` | SHOULD   | MUST     |
| `plain` | `code_verifier`                    | Fallback | Disallowed |

> **Recommendation:** Disable `plain` in production by calling `SetAllowPlain(false)` to comply with [RFC 9700 §2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1).

## Usage

`ProofKeyForCodeExchangeFlow` implements the `AuthorizationRequestValidator`, `TokenRequestValidator`, and `AuthCodeProcessor` extension interfaces. Register it with the Authorization Code flow via `cfg.RegisterExtension`.

### Basic setup (RFC 7636 defaults)

```go
pkce := rfc7636.New()

cfg := authorizationcode.NewConfig().
    SetClientManager(clientMgr).
    SetAuthCodeManager(authCodeMgr).
    SetTokenManager(tokenMgr).
    SetUserManager(userMgr).
    RegisterExtension(pkce)

flow, err := authorizationcode.Must(cfg)
```

### S256-only (recommended per RFC 9700)

```go
opts := rfc7636.NewOptions().
    SetAllowPlain(false)

pkce := rfc7636.New(opts)
```

### PKCE optional (not recommended for public clients)

```go
opts := rfc7636.NewOptions().
    SetRequired(false)

pkce := rfc7636.New(opts)
```

## Options

| Option        | Default | Description |
|---------------|---------|-------------|
| `required`    | `true`  | Enforce `code_challenge` for public clients (`token_endpoint_auth_method = none`). |
| `allowPlain`  | `true`  | Accept `plain` as a valid `code_challenge_method`. Set to `false` to enforce S256-only. |

## Validation Rules

### Authorization endpoint (`/authorize`)

- If `required = true` and the client is public: `code_challenge` **must** be present.
- If `code_challenge_method` is sent without `code_challenge`: error.
- Unsupported `code_challenge_method` values are rejected.
- If `code_challenge_method` is absent, defaults to `plain` (RFC 7636 §4.3).
- If `plain` is not allowed and the effective method is `plain`: error.
- `S256` challenges are validated against the base64url pattern (exactly 43 characters, no padding).
- `plain` challenges are validated against the `code_verifier` pattern (43–128 unreserved characters).

### Token endpoint (`/token`)

- If `required = true` and the client is public: `code_verifier` **must** be present.
- If the authorization code was issued with a `code_challenge`, `code_verifier` **must** be present.
- `code_verifier` must match the allowed character set and length (43–128 characters: `[A-Za-z0-9\-._~]`).
- If the stored `code_challenge_method` is missing (possible tampering), the request is rejected.
- The verified challenge must match the stored challenge; otherwise `invalid_grant` is returned.

## Security Notes

- The server enforces an explicit `code_challenge_method` when storing the authorization code, even when the client omits it (defaults to `plain`). This prevents silent downgrade attacks at token validation time (RFC 7636 Security Considerations).
- A `code_verifier` sent against an authorization code that was issued without PKCE is rejected with `invalid_grant`.
- A stored `code_challenge` with a missing `code_challenge_method` is treated as tampering and rejected.
