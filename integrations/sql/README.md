# integrations/sql

Reference implementations of the `models` interfaces backed by a SQL-friendly struct layout. Use these as a starting point — copy and adapt them to match your own database schema and ORM.

## Structs

| Struct              | Implements                              | File                    |
|---------------------|-----------------------------------------|-------------------------|
| `Client`            | `models.Client`                         | `client.go`             |
| `Token`             | `models.ExtendableToken`                | `token.go`              |
| `AuthorizationCode` | `models.ExtendableAuthorizationCode`    | `authorization_code.go` |
| `User`              | `models.User`                           | `user.go`               |

Each struct carries a compile-time assertion (e.g. `var _ models.Client = (*Client)(nil)`) so the compiler immediately reports any missing methods.

## Struct Fields

### Client

| Field                     | JSON key                    | Description                                      |
|---------------------------|-----------------------------|--------------------------------------------------|
| `ClientName`              | `client_name`               | Human-readable name                              |
| `ClientID`                | `client_id`                 | Unique client identifier                         |
| `ClientSecret`            | `client_secret`             | Credential for confidential clients              |
| `RedirectURIs`            | `redirect_uris`             | Allowed redirect URIs                            |
| `ResponseTypes`           | `response_types`            | Allowed response types (e.g. `code`)             |
| `GrantTypes`              | `grant_types`               | Allowed grant types (e.g. `authorization_code`)  |
| `Scopes`                  | `scopes`                    | Allowed scopes                                   |
| `TokenEndpointAuthMethod` | `token_endpoint_auth_method`| Auth method (e.g. `client_secret_basic`, `none`) |
| `ClientURI`               | `client_uri`                | Homepage of the client                           |
| `LogoURI`                 | `logo_uri`                  | Client logo URL                                  |
| `Contacts`                | `contacts`                  | Contact emails                                   |
| `TosURI`                  | `tos_uri`                   | Terms of service URL                             |
| `PolicyURI`               | `policy_uri`                | Privacy policy URL                               |
| `JWKsURI`                 | `jwks_uri`                  | JSON Web Key Set URL                             |
| `SoftwareID`              | `software_id`               | Software identifier (RFC 7591)                   |
| `SoftwareVersion`         | `software_version`          | Software version (RFC 7591)                      |
| `CreatedAt`               | `created_at`                | Record creation time                             |
| `UpdatedAt`               | `updated_at`                | Record last update time                          |

### Token

| Field                   | JSON key                  | Description                                      |
|-------------------------|---------------------------|--------------------------------------------------|
| `TokenType`             | `token_type`              | Token type (e.g. `Bearer`)                       |
| `AccessToken`           | `access_token`            | Access token string                              |
| `RefreshToken`          | `refresh_token`           | Refresh token string                             |
| `ClientID`              | `client_id`               | Client the token was issued to                   |
| `Scopes`                | `scopes`                  | Granted scopes                                   |
| `IssuedAt`              | `issued_at`               | Issuance time                                    |
| `AccessTokenExpiresIn`  | `access_token_expires_in` | Access token lifetime                            |
| `RefreshTokenExpiresIn` | `refresh_token_expires_in`| Refresh token lifetime                           |
| `UserID`                | `user_id`                 | Resource owner (empty for client credentials)    |
| `JwtID`                 | `jti`                     | JWT ID for RFC 9068 access tokens                |
| `Data`                  | `data`                    | Application-specific extra data                  |
| `CreatedAt`             | `created_at`              | Record creation time                             |
| `UpdatedAt`             | `updated_at`              | Record last update time                          |

### AuthorizationCode

| Field                 | JSON key               | Description                              |
|-----------------------|------------------------|------------------------------------------|
| `Code`                | `code`                 | Authorization code string                |
| `ClientID`            | `client_id`            | Client the code was issued to            |
| `UserID`              | `user_id`              | User who authorized the request          |
| `RedirectURI`         | `redirect_uri`         | Redirect URI from the authorization request |
| `ResponseType`        | `response_type`        | Response type (e.g. `code`)              |
| `Scopes`              | `scopes`               | Approved scopes                          |
| `Nonce`               | `nonce`                | OIDC nonce value                         |
| `State`               | `state`                | State parameter echoed from the request  |
| `AuthTime`            | `auth_time`            | Time the user authenticated              |
| `ExpiresIn`           | `expires_in`           | Code lifetime                            |
| `CodeChallenge`       | `code_challenge`       | PKCE code challenge (RFC 7636)           |
| `CodeChallengeMethod` | `code_challenge_method`| PKCE challenge method (`plain` or `S256`)|
| `Data`                | `data`                 | Application-specific extra data          |
| `CreatedAt`           | `created_at`           | Record creation time                     |
| `UpdatedAt`           | `updated_at`           | Record last update time                  |

### User

| Field    | JSON key  | Description            |
|----------|-----------|------------------------|
| `UserID` | `user_id` | Unique user identifier |

## Notable Behaviours

- **`CheckClientSecret`** uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks when comparing secrets.
- **`GetAllowedScopes`** filters the requested scopes against the client's registered scopes and returns only the intersection.
- **`GetDefaultRedirectURI`** returns the first URI in `RedirectURIs`, or an empty string if none are registered.
- **`IsPublic`** returns `true` when `TokenEndpointAuthMethod` is `none`.
- **`CheckTokenEndpointAuthMethod`** ignores the `endpoint` parameter — this implementation uses a single auth method for all endpoints.
- **`Data` field** on `Token` and `AuthorizationCode` backs `GetExtraData`/`SetExtraData`, satisfying `models.ExtendableToken` and `models.ExtendableAuthorizationCode` respectively.
