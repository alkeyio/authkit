// Package types defines domain value types used throughout authkit. Each type
// wraps a primitive (string, *uint, etc.) and provides named predicates and
// constants so callers can write expressive, type-safe comparisons without
// stringly-typed checks.
package types

// SpaceDelimitedArray is a list of strings carried as a space-delimited value,
// as used for ACR values in OpenID Connect requests.
type SpaceDelimitedArray []string
