# rfc6749 — OAuth 2.0 Authorization Framework

Package directory `rfc6749` implements the [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749).

It provides grant flows, client authentication, and authorization code generation as composable sub-packages. All flows are wired through the `authkit.Server` dispatcher at the root package.

## Package Structure

| Package                  | Description                                                         |
|--------------------------|---------------------------------------------------------------------|
| `authorization_code`     | Authorization Code Grant (RFC 6749 §4.1). Supports PKCE and OIDC extensions. |
| `ropc`                   | Resource Owner Password Credentials Grant (RFC 6749 §4.3). Legacy; see warning. |
| `client_credentials`     | Client Credentials Grant (RFC 6749 §4.4). Confidential clients only; no refresh token. |
| `client_authentication`  | Client authentication handlers (`client_secret_basic`, `client_secret_post`, `none`). |
| `code_generator`         | Default authorization code generator used by the Authorization Code flow. |

## Sub-package Documentation

| Package                                              | README                                      |
|------------------------------------------------------|---------------------------------------------|
| `rfc6749/authorization_code`                         | [README](authorization_code/README.md)      |
| `rfc6749/ropc`                                       | [README](ropc/README.md)                    |
| `rfc6749/client_credentials`                         | [README](client_credentials/README.md)      |
| `rfc6749/client_authentication`                      | [README](client_authentication/README.md)   |
| `rfc6749/code_generator`                             | [README](code_generator/README.md)          |
