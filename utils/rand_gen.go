package utils

import (
	"crypto/rand"
	"math/big"
)

// Character set variables used as the charset argument to GenerateRandString
// and GenerateRandRune.
var (
	// AlphaNum contains all ASCII letters and digits.
	AlphaNum = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	// SecretCharset contains ASCII letters, digits, and URL-safe special characters
	// suitable for generating client secrets and opaque tokens.
	SecretCharset = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.~")
)

// GenerateRandRune returns a cryptographically secure random rune slice of
// length l drawn from charset.
func GenerateRandRune(l int, charset []rune) (seq []rune, err error) {
	c := big.NewInt(int64(len(charset)))
	seq = make([]rune, l)

	for i := 0; i < l; i++ {
		r, err := rand.Int(rand.Reader, c)
		if err != nil {
			return seq, err
		}

		rn := charset[r.Uint64()]
		seq[i] = rn
	}

	return seq, nil
}

// GenerateRandString returns a cryptographically secure random string of
// length l drawn from charset.
func GenerateRandString(l int, charset []rune) (string, error) {
	seq, err := GenerateRandRune(l, charset)
	if err != nil {
		return "", err
	}

	return string(seq), nil
}
