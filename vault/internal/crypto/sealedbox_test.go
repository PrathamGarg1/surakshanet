package crypto

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestParentKeySaveLoadAndSealOpen(t *testing.T) {
	mat, err := GenerateParentKeyMaterial("Test Parent")
	if err != nil {
		t.Fatalf("GenerateParentKeyMaterial: %v", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "parent.key.json")

	if err := SaveEncryptedKeyFile(keyPath, mat, "short"); err == nil {
		t.Fatal("expected error for short passphrase")
	}
	if err := SaveEncryptedKeyFile(keyPath, mat, "correct-horse-battery"); err != nil {
		t.Fatalf("SaveEncryptedKeyFile: %v", err)
	}
	if _, err := LoadEncryptedKeyFile(keyPath, "wrong-passphrase"); err == nil {
		t.Fatal("expected error with wrong passphrase")
	}

	loaded, err := LoadEncryptedKeyFile(keyPath, "correct-horse-battery")
	if err != nil {
		t.Fatalf("LoadEncryptedKeyFile: %v", err)
	}
	if loaded.KeyID != mat.KeyID {
		t.Fatalf("KeyID mismatch: got %s want %s", loaded.KeyID, mat.KeyID)
	}

	plaintext := []byte(`{"contact":"Unknown","text":"तुम बेकार हो — don't tell your parents"}`)
	box, err := Seal(plaintext, loaded.ECDHPublicRaw)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	decrypted, err := Open(box, loaded.ECDHPrivate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
	}

	// Wrong private key must fail.
	other, err := GenerateParentKeyMaterial("Other Parent")
	if err != nil {
		t.Fatalf("GenerateParentKeyMaterial other: %v", err)
	}
	if _, err := Open(box, other.ECDHPrivate); err == nil {
		t.Fatal("expected Open to fail with wrong private key")
	}

	// Tampering 1 bit in ciphertext must fail GCM authentication.
	ctBytes, _ := base64.StdEncoding.DecodeString(box.CT)
	ctBytes[0] ^= 0x01
	tampered := *box
	tampered.CT = base64.StdEncoding.EncodeToString(ctBytes)
	if _, err := Open(&tampered, loaded.ECDHPrivate); err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext")
	}
}
