package utils

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrUnsupportedSigningMethod is returned by ParseSigningKey when the signing
// method algorithm prefix is not recognised.
var ErrUnsupportedSigningMethod = errors.New("unsupported signing method")

type (
	// JWTToken holds a parsed signing key and its associated metadata, and
	// provides a Generate method to produce signed JWT strings.
	JWTToken struct {
		signingKeyID  string
		signingKey    interface{}
		signingMethod jwt.SigningMethod
	}

	// JWTHeader is a free-form map of additional JWT header parameters.
	JWTHeader map[string]interface{}
	// JWTClaim is a free-form map of JWT claims.
	JWTClaim map[string]interface{}
)

// NewJWTToken parses signingKey for the given signingMethod and returns a
// JWTToken ready to sign tokens. An optional key ID (kid) can be supplied as
// the first element of args.
func NewJWTToken(signingKey []byte, signingMethod jwt.SigningMethod, args ...string) (*JWTToken, error) {
	var keyID string
	if len(args) > 0 {
		keyID = args[0]
	}

	key, err := ParseSigningKey(signingKey, signingMethod)
	if err != nil {
		return nil, err
	}

	return &JWTToken{
		signingKeyID:  keyID,
		signingKey:    key,
		signingMethod: signingMethod,
	}, nil
}

// KeyID returns the key ID associated with this token, or an empty string if
// none was provided.
func (t *JWTToken) KeyID() string {
	return t.signingKeyID
}

// SigningKey returns the parsed signing key.
func (t *JWTToken) SigningKey() interface{} {
	return t.signingKey
}

// SigningMethod returns the signing method used by this token.
func (t *JWTToken) SigningMethod() jwt.SigningMethod {
	return t.signingMethod
}

// Generate produces a signed JWT string from claims and additional headers.
// The "iat" claim is always set to the current UTC time. If a key ID was
// provided, it is added as the "kid" header parameter.
func (t *JWTToken) Generate(claims JWTClaim, headers JWTHeader) (string, error) {
	mapClaims := jwt.MapClaims{
		"iat": jwt.NewNumericDate(time.Now().UTC().Round(time.Second)),
	}
	for k := range claims {
		mapClaims[k] = claims[k]
	}

	token := jwt.NewWithClaims(t.signingMethod, mapClaims)
	for k, v := range headers {
		token.Header[k] = v
	}

	if t.signingKeyID != "" {
		token.Header["kid"] = t.signingKeyID
	}

	return token.SignedString(t.signingKey)
}

// ParseSigningKey parses signingKey into the concrete key type expected by
// signingMethod. Supported algorithm prefixes: ES (ECDSA), RS/PS (RSA),
// HS (HMAC), Ed (EdDSA). Returns ErrUnsupportedSigningMethod for any other
// algorithm.
func ParseSigningKey(signingKey []byte, signingMethod jwt.SigningMethod) (interface{}, error) {
	alg := signingMethod.Alg()
	if strings.HasPrefix(alg, "ES") {
		return jwt.ParseECPrivateKeyFromPEM(signingKey)
	}

	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		return jwt.ParseRSAPrivateKeyFromPEM(signingKey)
	}

	if strings.HasPrefix(alg, "HS") {
		return signingKey, nil
	}

	if strings.HasPrefix(alg, "Ed") {
		return jwt.ParseEdPrivateKeyFromPEM(signingKey)
	}

	return nil, ErrUnsupportedSigningMethod
}
