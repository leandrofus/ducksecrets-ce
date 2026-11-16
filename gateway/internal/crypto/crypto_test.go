package crypto

import (
	"bytes"
	"testing"
)

func TestVault_EncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	vault, err := NewVault(key)
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	secretPayload := []byte("SUPER_SECRET_DATABASE_URL=postgres://user:pass@localhost:5432/production")

	ciphertext, nonce, err := vault.Encrypt(secretPayload)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(nonce) != NonceSize {
		t.Fatalf("expected nonce size %d, got %d", NonceSize, len(nonce))
	}

	decrypted, err := vault.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, secretPayload) {
		t.Fatalf("decrypted payload mismatch. expected %q, got %q", secretPayload, decrypted)
	}
}

func TestVault_UniqueNonces(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	vault, _ := NewVault(key)

	payload := []byte("constant_secret")
	c1, n1, err := vault.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	c2, n2, err := vault.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(n1, n2) {
		t.Fatal("two encryptions must never use the same nonce")
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of same plaintext must produce different ciphertexts")
	}
}

func TestVault_TamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	vault, _ := NewVault(key)

	ciphertext, nonce, _ := vault.Encrypt([]byte("critical-secret"))

	// Tamper with one byte of the ciphertext
	ciphertext[0] ^= 0xFF

	_, err := vault.Decrypt(ciphertext, nonce)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed on tampered ciphertext, got %v", err)
	}
}

func TestVault_InvalidNonceSize(t *testing.T) {
	key, _ := GenerateKey()
	vault, _ := NewVault(key)

	ciphertext, _, _ := vault.Encrypt([]byte("foo"))

	_, err := vault.Decrypt(ciphertext, []byte("short-nonce"))
	if err != ErrInvalidNonceSize {
		t.Fatalf("expected ErrInvalidNonceSize, got %v", err)
	}
}

func TestVault_InvalidKeySize(t *testing.T) {
	_, err := NewVault([]byte("too-short"))
	if err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestVault_DeriveSubVault(t *testing.T) {
	masterKey, _ := GenerateKey()
	masterVault, _ := NewVault(masterKey)

	proj1Vault, err := masterVault.DeriveSubVault("project", "proj_alpha")
	if err != nil {
		t.Fatalf("DeriveSubVault failed: %v", err)
	}

	proj2Vault, err := masterVault.DeriveSubVault("project", "proj_beta")
	if err != nil {
		t.Fatalf("DeriveSubVault failed: %v", err)
	}

	payload := []byte("api_key_12345")
	c1, n1, _ := proj1Vault.Encrypt(payload)

	// proj1 should be able to decrypt
	dec, err := proj1Vault.Decrypt(c1, n1)
	if err != nil || !bytes.Equal(dec, payload) {
		t.Fatalf("proj1Vault failed to decrypt own payload")
	}

	// proj2 must NOT be able to decrypt proj1's ciphertext
	_, err = proj2Vault.Decrypt(c1, n1)
	if err != ErrDecryptionFailed {
		t.Fatalf("proj2Vault should fail to decrypt proj1 payload, got %v", err)
	}
}

func TestVault_AADAndHardening(t *testing.T) {
	if _, err := DeriveKey(nil, nil, "info"); err != ErrEmptySecret {
		t.Fatalf("expected ErrEmptySecret, got %v", err)
	}

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	vault, err := NewVault(key)
	if err != nil {
		t.Fatal(err)
	}

	aad := []byte("proj-1:prod:DB_PASS:v1")
	ct, nonce, err := vault.EncryptWithAAD([]byte("secret-value"), aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}
	pt, err := vault.DecryptWithAAD(ct, nonce, aad)
	if err != nil || !bytes.Equal(pt, []byte("secret-value")) {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}
	if _, err := vault.DecryptWithAAD(ct, nonce, []byte("proj-1:staging:DB_PASS:v1")); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed on wrong AAD, got %v", err)
	}
	if _, err := vault.Decrypt(ct, nonce); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed on missing AAD, got %v", err)
	}

	for _, bad := range [][2]string{
		{"", "id"},
		{"project", ""},
		{"project:sub", "id"},
		{"pro\x00ject", "id"},
		{"project", "id\x001"},
	} {
		if _, err := vault.DeriveSubVault(bad[0], bad[1]); err != ErrInvalidSubVaultInput {
			t.Fatalf("DeriveSubVault(%q, %q) = %v, want ErrInvalidSubVaultInput", bad[0], bad[1], err)
		}
	}

	vault.Close()
	for i, b := range vault.key {
		if b != 0 {
			t.Fatalf("vault.key[%d] = %d after Close, want 0", i, b)
		}
	}
	if _, _, err := vault.Encrypt([]byte("x")); err != ErrVaultClosed {
		t.Fatalf("Encrypt after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := vault.Decrypt(ct, nonce); err != ErrVaultClosed {
		t.Fatalf("Decrypt after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := vault.DeriveSubVault("project", "p1"); err != ErrVaultClosed {
		t.Fatalf("DeriveSubVault after Close = %v, want ErrVaultClosed", err)
	}
}
