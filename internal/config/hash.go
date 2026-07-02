package config

import (
	"crypto/sha256"
	"encoding/hex"
)

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
