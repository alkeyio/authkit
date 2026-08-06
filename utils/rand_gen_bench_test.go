package utils

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// naiveGenerateRandString is a reference implementation that makes one
// crypto/rand call per character.
// It exists only to provide a baseline for the benchmark below.
func naiveGenerateRandString(l int, charset []rune) (string, error) {
	charsetLen := int64(len(charset))
	seq := make([]rune, l)
	for i := 0; i < l; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(charsetLen))
		if err != nil {
			return "", err
		}
		seq[i] = charset[n.Int64()]
	}
	return string(seq), nil
}

func BenchmarkGenerateRandString_BatchRead(b *testing.B) {
	for b.Loop() {
		if _, err := GenerateRandString(32, AlphaNum); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateRandString_NaivePerChar(b *testing.B) {
	for b.Loop() {
		if _, err := naiveGenerateRandString(32, AlphaNum); err != nil {
			b.Fatal(err)
		}
	}
}
