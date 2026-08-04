package models

// User represents an authenticated end-user. The interface is intentionally
// minimal — only a stable unique identifier is required — so that any user
// model (database row, JWT claims, session struct) can satisfy it without
// changes to the core library.
type User interface {
	// GetUserID returns the unique identifier of the user (e.g. UUID, email,
	// or username). This value is used as the "sub" claim in JWT access tokens
	// and stored on authorization codes and tokens.
	GetUserID() string
}
