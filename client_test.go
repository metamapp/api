package api

import (
	"testing"
)

func TestLoadKey(t *testing.T) {
	src, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %s", err)
	}
	raw := src.RawPrivateKey()
	dst, err := LoadKey(raw)
	if err != nil {
		t.Fatalf("Failed to load key: %s", err)
	}
	if src.publicKey != dst.publicKey {
		t.Fatalf("Mismatching public key from imported key")
	}
	if src.privateKey.Key.Bytes() != dst.privateKey.Key.Bytes() {
		t.Fatalf("Mismatching private key from imported key")
	}
}
