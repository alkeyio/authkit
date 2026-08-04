package codegen

import (
	"time"

	"github.com/tniah/authkit/models"
	"github.com/tniah/authkit/requests"
	"github.com/tniah/authkit/types"
)

// ExpiresInGenerator returns the authorization code lifetime for the given
// grant type and client. Implement this to apply per-client expiry policies.
type ExpiresInGenerator func(gt types.GrantType, client models.Client) time.Duration

// RandStringGenerator produces the authorization code value for the given
// grant type and client. Implement this to replace the built-in crypto/rand
// generator (e.g. to use a different encoding or length strategy).
type RandStringGenerator func(gt types.GrantType, client models.Client) (string, error)

// ExtraDataGenerator attaches arbitrary metadata to the authorization code
// (e.g. PKCE code_challenge, session identifiers). The returned map is stored
// via ExtendableAuthorizationCode.SetExtraData.
type ExtraDataGenerator func(r *requests.AuthorizationRequest) (map[string]interface{}, error)
