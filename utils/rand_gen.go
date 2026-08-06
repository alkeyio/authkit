package utils

import (
	"crypto/rand"
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
//
// Random bytes are read in a single batch rather than one call per character.
// Rejection sampling is used to eliminate modulo bias: a byte is accepted only
// when it falls below the largest multiple of len(charset) that fits in a byte,
// ensuring each charset index is equally probable.
func GenerateRandRune(l int, charset []rune) ([]rune, error) {
	charsetLen := len(charset)
	seq := make([]rune, l)

	// threshold is the largest multiple of charsetLen that fits in [0, 256).
	// Bytes in [0, threshold) are accepted; bytes in [threshold, 256) are
	// rejected to avoid modulo bias.
	threshold := 256 - (256 % charsetLen)

	// Read a batch of bytes sized to handle rejections with high probability.
	// Worst-case acceptance rate is ~50% (charset length just above 128), so
	// 2*l+64 bytes is sufficient for any practical token length.
	buf := make([]byte, 2*l+64)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}

	written := 0
	for _, b := range buf {
		if written == l {
			break
		}
		if int(b) < threshold {
			seq[written] = charset[int(b)%charsetLen]
			written++
		}
	}

	// Fallback for the extremely unlikely case where the initial batch did not
	// contain enough accepted bytes (requires sustained ~50% rejection rate).
	for written < l {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		if int(b[0]) < threshold {
			seq[written] = charset[int(b[0])%charsetLen]
			written++
		}
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
