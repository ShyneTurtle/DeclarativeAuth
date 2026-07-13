package auth

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h := &Hasher{Params: DefaultArgon2Params}
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
	h := &Hasher{Params: DefaultArgon2Params}
	encoded, _ := h.Hash("correct-horse-battery-staple")
	ok, err := h.Verify("wrong-password", encoded)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to fail verification")
	}
}

func TestHash_UniqueSaltsPerCall(t *testing.T) {
	h := &Hasher{Params: DefaultArgon2Params}
	a, _ := h.Hash("same-password")
	b, _ := h.Hash("same-password")
	if a == b {
		t.Fatal("expected distinct hashes for the same password due to random salt")
	}
}

func TestHasher_Dummy(t *testing.T) {
	h := &Hasher{Params: DefaultArgon2Params}
	hash := h.Dummy()
	if !ValidHashFormat(hash) {
		t.Fatalf("expected Dummy() to return a well-formed argon2id hash, got %q", hash)
	}
	if again := h.Dummy(); again != hash {
		t.Fatalf("expected Dummy() to cache and return the same hash on repeated calls, got %q then %q", hash, again)
	}
}
