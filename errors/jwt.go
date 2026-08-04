package errors

import "errors"

// JWT signing configuration errors.
var (
	ErrMissingIssuer           = errors.New("\"issuer\" or \"issuerGenerator\" is required")
	ErrMissingAudience         = errors.New("\"audience\" or \"audienceGenerator\" is required")
	ErrMissingExpiresIn        = errors.New("\"expiresIn\" or \"expiresInGenerator\" is required")
	ErrMissingSigningKey       = errors.New("\"signingKey\" or \"signingKeyGenerator\" is required")
	ErrMissingSigningKeyMethod = errors.New("\"signingKeyMethod\" is required")
	// ErrInsecureSigningMethod is returned when the signing method is "none",
	// which is prohibited by RFC 9068 §2.1.
	ErrInsecureSigningMethod = errors.New("signing method \"none\" is not allowed")
)
