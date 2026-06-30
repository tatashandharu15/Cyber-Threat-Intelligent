package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

// genRSAKeyPEMs produces a fresh RSA keypair as PKCS8 private-key PEM and PKIX
// public-key PEM strings.
func genRSAKeyPEMs(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privPEM, pubPEM
}

// TestRS256IssueVerifyJWKS exercises the RS256 path end to end via env-driven
// NewIssuer: issue a token, verify it, and confirm the JWKS exposes the kid.
func TestRS256IssueVerifyJWKS(t *testing.T) {
	privPEM, pubPEM := genRSAKeyPEMs(t)
	t.Setenv("JWT_ALG", "RS256")
	t.Setenv("JWT_PRIVATE_KEY", privPEM)
	t.Setenv("JWT_PUBLIC_KEY", pubPEM)

	iss := NewIssuer("ignored-secret", time.Hour)
	if iss.alg != algRS256 {
		t.Fatalf("expected RS256 issuer, got alg=%q", iss.alg)
	}
	if iss.kid == "" {
		t.Fatal("expected non-empty kid")
	}

	tok, err := iss.Issue("user-1", "tenant-1", "jti-1", []string{"analyst"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.TenantID != "tenant-1" || claims.ID != "jti-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !claims.HasPermission("read") || !claims.HasRole("analyst") {
		t.Fatalf("missing role/permission: %+v", claims)
	}

	raw, err := iss.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	var doc struct {
		Keys []struct {
			Kty, Use, Alg, Kid, N, E string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kid != iss.kid {
		t.Fatalf("jwks kid %q != issuer kid %q", k.Kid, iss.kid)
	}
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" || k.N == "" || k.E == "" {
		t.Fatalf("malformed jwk: %+v", k)
	}
}

// TestHS256DefaultStillWorks confirms that with no JWT_ALG env the issuer stays
// HS256 and its JWKS is an empty key set (never exposing the secret).
func TestHS256DefaultStillWorks(t *testing.T) {
	iss := NewIssuer("test-secret", time.Hour)
	if iss.alg != algHS256 {
		t.Fatalf("expected HS256 default, got %q", iss.alg)
	}
	tok, err := iss.Issue("u", "tn", "j", nil, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	raw, err := iss.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if string(raw) != `{"keys":[]}` {
		t.Fatalf("expected empty jwks, got %s", raw)
	}
}
