// Package auth issues and verifies the platform JWT and exposes middleware that
// makes the authenticated actor and tenant available to handlers. The claim set
// matches the API Blueprint section 4.1.
//
// By default tokens are signed with HS256 using a shared secret, which keeps
// local development and the MVP backend simple. The Security Blueprint specifies
// RS256 with externally managed keys for production; this is selected at runtime
// via the JWT_ALG environment variable (see NewIssuer) without changing the
// *Issuer type that services pass around.
package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signing algorithms supported by the Issuer.
const (
	algHS256 = "HS256"
	algRS256 = "RS256"
)

// Claims is the platform JWT claim set.
type Claims struct {
	TenantID    string   `json:"tenant_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// Issuer signs and verifies platform JWTs. It supports HS256 (shared secret,
// the default) and RS256 (RSA keypair, selected via JWT_ALG=RS256).
type Issuer struct {
	alg string
	ttl time.Duration

	// HS256
	secret []byte

	// RS256
	privateKey *rsa.PrivateKey // optional; present on the signer (auth-service)
	publicKey  *rsa.PublicKey  // used for verification and JWKS
	kid        string
}

// NewIssuer returns an Issuer using the given token lifetime. The signing
// algorithm is selected from the environment:
//
//   - JWT_ALG=RS256 builds an RS256 issuer from JWT_PRIVATE_KEY (PEM, PKCS1 or
//     PKCS8; optional, only the signer needs it) and JWT_PUBLIC_KEY (PEM PKIX,
//     used for verification and the JWKS document). The key id (kid) is derived
//     from a SHA-256 over the public key DER.
//   - Anything else (unset or HS256) behaves exactly as before: HS256 using
//     secret. If RS256 is requested but key parsing fails, the issuer falls back
//     to HS256 so builds/tests with no key material still work.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	if os.Getenv("JWT_ALG") == algRS256 {
		if iss, err := newRS256Issuer(ttl); err == nil {
			return iss
		}
		// Fall through to HS256 on any parsing error.
	}
	return &Issuer{alg: algHS256, secret: []byte(secret), ttl: ttl}
}

// newRS256Issuer constructs an RS256 issuer from the JWT_PRIVATE_KEY and
// JWT_PUBLIC_KEY environment variables. At least a public key is required to
// verify tokens and serve a JWKS; the private key is only needed to sign.
func newRS256Issuer(ttl time.Duration) (*Issuer, error) {
	iss := &Issuer{alg: algRS256, ttl: ttl}

	if privPEM := os.Getenv("JWT_PRIVATE_KEY"); privPEM != "" {
		priv, err := parseRSAPrivateKey([]byte(privPEM))
		if err != nil {
			return nil, err
		}
		iss.privateKey = priv
		iss.publicKey = &priv.PublicKey
	}

	if pubPEM := os.Getenv("JWT_PUBLIC_KEY"); pubPEM != "" {
		pub, err := parseRSAPublicKey([]byte(pubPEM))
		if err != nil {
			return nil, err
		}
		iss.publicKey = pub
	}

	if iss.publicKey == nil {
		return nil, fmt.Errorf("RS256 requires JWT_PUBLIC_KEY or JWT_PRIVATE_KEY")
	}
	iss.kid = deriveKID(iss.publicKey)
	return iss, nil
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key in either PKCS1 or
// PKCS8 form.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("parse RSA private key: no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parse RSA private key: not an RSA key")
	}
	return key, nil
}

// parseRSAPublicKey parses a PEM-encoded PKIX RSA public key.
func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("parse RSA public key: no PEM block found")
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA public key: %w", err)
	}
	key, ok := keyAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parse RSA public key: not an RSA key")
	}
	return key, nil
}

// deriveKID derives a stable key id as the hex of the first 16 bytes of a
// SHA-256 over the public key DER.
func deriveKID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:16])
}

// Issue mints a signed token for the given subject (user id), tenant, session id
// (jti), roles and permissions.
func (i *Issuer) Issue(userID, tenantID, jti string, roles, perms []string) (string, error) {
	now := time.Now()
	claims := Claims{
		TenantID:    tenantID,
		Roles:       roles,
		Permissions: perms,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}

	if i.alg == algRS256 {
		if i.privateKey == nil {
			return "", fmt.Errorf("sign token: RS256 issuer has no private key")
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if i.kid != "" {
			tok.Header["kid"] = i.kid
		}
		signed, err := tok.SignedString(i.privateKey)
		if err != nil {
			return "", fmt.Errorf("sign token: %w", err)
		}
		return signed, nil
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a signed token, returning its claims.
func (i *Issuer) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if i.alg == algRS256 {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return i.publicKey, nil
		}
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	return claims, nil
}

// jwk is a single JSON Web Key entry.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// JWKS returns the JSON Web Key Set document for this issuer. For RS256 with a
// public key it contains the single RSA verification key; for HS256 (or RS256
// with no public key) it returns an empty key set, since symmetric secrets must
// never be published.
func (i *Issuer) JWKS() ([]byte, error) {
	if i.alg == algRS256 && i.publicKey != nil {
		n := base64.RawURLEncoding.EncodeToString(i.publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i.publicKey.E)).Bytes())
		doc := jwks{Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Alg: algRS256,
			Kid: i.kid,
			N:   n,
			E:   e,
		}}}
		return json.Marshal(doc)
	}
	return json.Marshal(jwks{Keys: []jwk{}})
}

// HasRole reports whether the claims include role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission reports whether the claims include permission.
func (c *Claims) HasPermission(perm string) bool {
	for _, p := range c.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}
