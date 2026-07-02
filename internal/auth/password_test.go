package auth

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h := &Hasher{Pepper: []byte("test-pepper"), Params: DefaultArgon2Params}
	encoded, err := h.Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	ok, err := h.Verify("correct-horse-battery-staple", encoded)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	h := &Hasher{Pepper: []byte("test-pepper"), Params: DefaultArgon2Params}
	encoded, _ := h.Hash("correct-horse-battery-staple")
	ok, err := h.Verify("wrong-password", encoded)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to fail verification")
	}
}

func TestVerify_DifferentPepperFails(t *testing.T) {
	h1 := &Hasher{Pepper: []byte("pepper-one"), Params: DefaultArgon2Params}
	h2 := &Hasher{Pepper: []byte("pepper-two"), Params: DefaultArgon2Params}
	encoded, _ := h1.Hash("secret")
	ok, err := h2.Verify("secret", encoded)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with a different pepper")
	}
}

func TestHash_UniqueSaltsPerCall(t *testing.T) {
	h := &Hasher{Pepper: []byte("test-pepper"), Params: DefaultArgon2Params}
	a, _ := h.Hash("same-password")
	b, _ := h.Hash("same-password")
	if a == b {
		t.Fatal("expected distinct hashes for the same password due to random salt")
	}
}
