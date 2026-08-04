// Package utils provides internal helpers for authkit: cryptographically
// secure random string generation, JWT signing, HTTP response utilities,
// and nil-safe reflection helpers.
package utils

import "reflect"

// IsNil reports whether i is nil, correctly handling typed nils (e.g. a nil
// pointer stored in an interface value). A plain `i == nil` check returns
// false for typed nils; this function uses reflection to detect them.
func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}

	v := reflect.ValueOf(i)
	if !v.IsValid() {
		return true
	}

	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
