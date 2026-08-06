package oidcserver

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndParseKey_ES256RoundTrip(t *testing.T) {
	key, pemStr, err := generateKey("ES256")
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if key.Algorithm != "ES256" || key.Kid == "" {
		t.Fatalf("unexpected key: %+v", key)
	}
	if key.SigningMethod() != jwt.SigningMethodES256 {
		t.Errorf("expected ES256 signing method")
	}

	parsed, err := parseKey(key.Kid, key.Algorithm, pemStr)
	if err != nil {
		t.Fatalf("parseKey: %v", err)
	}
	if parsed.Kid != key.Kid || parsed.Algorithm != "ES256" {
		t.Fatalf("round-tripped key mismatch: %+v vs %+v", parsed, key)
	}

	jwk, err := parsed.JWK()
	if err != nil {
		t.Fatalf("JWK: %v", err)
	}
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" || jwk["kid"] != key.Kid {
		t.Errorf("unexpected EC JWK: %+v", jwk)
	}
	if jwk["x"] == "" || jwk["y"] == "" {
		t.Errorf("expected non-empty EC coordinates: %+v", jwk)
	}
}

func TestGenerateAndParseKey_RS256RoundTrip(t *testing.T) {
	key, pemStr, err := generateKey("RS256")
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if key.Algorithm != "RS256" || key.Kid == "" {
		t.Fatalf("unexpected key: %+v", key)
	}
	if key.SigningMethod() != jwt.SigningMethodRS256 {
		t.Errorf("expected RS256 signing method")
	}

	parsed, err := parseKey(key.Kid, key.Algorithm, pemStr)
	if err != nil {
		t.Fatalf("parseKey: %v", err)
	}

	jwk, err := parsed.JWK()
	if err != nil {
		t.Fatalf("JWK: %v", err)
	}
	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" || jwk["kid"] != key.Kid {
		t.Errorf("unexpected RSA JWK: %+v", jwk)
	}
	if jwk["n"] == "" || jwk["e"] == "" {
		t.Errorf("expected non-empty RSA modulus/exponent: %+v", jwk)
	}
}

func TestGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	if _, _, err := generateKey("HS256"); err == nil {
		t.Fatal("expected an error for an unsupported algorithm")
	}
}

func TestParseKey_InvalidPEM(t *testing.T) {
	if _, err := parseKey("kid", "ES256", "not a pem block"); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}
