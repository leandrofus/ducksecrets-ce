// Package crypto implements the core envelope encryption engine for DuckSecrets.
// It uses AES-256-GCM with unique 96-bit nonces and HKDF-SHA256 for sub-key derivation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the required size of an AES-256 key in bytes.
	KeySize = 32
	// NonceSize is the standard GCM nonce size in bytes (96 bits).
	NonceSize = 12
)

var (
	ErrInvalidKeySize       = errors.New("crypto: invalid key size, must be 32 bytes for AES-256")
	ErrInvalidNonceSize     = errors.New("crypto: invalid nonce size, must be 12 bytes")
	ErrDecryptionFailed     = errors.New("crypto: decryption failed (tampered ciphertext or invalid key)")
	ErrEmptySecret          = errors.New("crypto: empty secret for key derivation")
	ErrInvalidSubVaultInput = errors.New("crypto: invalid sub-vault scope or identifier")
	ErrVaultClosed          = errors.New("crypto: vault closed")
)

// Vault wraps an AES-256-GCM block cipher.
type Vault struct {
	aead cipher.AEAD
	key  []byte
}

// NewVault creates a new Vault engine from a 32-byte master key.
func NewVault(masterKey []byte) (*Vault, error) {
	if len(masterKey) != KeySize {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: create gcm: %w", err)
	}
	keyCopy := make([]byte, KeySize)
	copy(keyCopy, masterKey)
	return &Vault{
		aead: aead,
		key:  keyCopy,
	}, nil
}

// GenerateKey generates a cryptographically secure random 32-byte key.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("crypto: generate random key: %w", err)
	}
	return k, nil
}

// DeriveKey derives a 32-byte key from a secret, salt, and domain separation info tag.
func DeriveKey(secret, salt []byte, info string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	k := make([]byte, KeySize)
	h := hkdf.New(sha256.New, secret, salt, []byte(info))
	if _, err := io.ReadFull(h, k); err != nil {
		return nil, fmt.Errorf("crypto: derive key: %w", err)
	}
	return k, nil
}

// Close zeros the in-memory key copy and disables further cryptographic operations.
func (v *Vault) Close() {
	if v == nil {
		return
	}
	clear(v.key)
	v.aead = nil
}

// DeriveSubVault derives a project- or environment-specific Vault instance.
func (v *Vault) DeriveSubVault(scope, identifier string) (*Vault, error) {
	if v == nil || v.aead == nil || len(v.key) == 0 {
		return nil, ErrVaultClosed
	}
	// Reject empty inputs, NUL bytes, or delimiter colons in scope so two distinct
	// (scope, identifier) pairs cannot alias the same HKDF domain tag.
	if scope == "" || identifier == "" || strings.ContainsAny(scope, ":\x00") || strings.ContainsRune(identifier, 0) {
		return nil, ErrInvalidSubVaultInput
	}
	info := fmt.Sprintf("ducksecrets:%s:%s", scope, identifier)
	subKey, err := DeriveKey(v.key, nil, info)
	if err != nil {
		return nil, err
	}
	defer clear(subKey)
	return NewVault(subKey)
}

// Encrypt encrypts plaintext with AES-256-GCM using a freshly generated 12-byte random nonce.
// Returns the ciphertext and the nonce.
func (v *Vault) Encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	return v.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD encrypts plaintext with AES-256-GCM using a freshly generated
// 12-byte random nonce and authenticates aad without including it in ciphertext.
func (v *Vault) EncryptWithAAD(plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	if v == nil || v.aead == nil {
		return nil, nil, ErrVaultClosed
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	ciphertext = v.aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using the provided 12-byte nonce.
// Returns ErrDecryptionFailed if the tag does not match or the ciphertext is tampered.
func (v *Vault) Decrypt(ciphertext, nonce []byte) ([]byte, error) {
	return v.DecryptWithAAD(ciphertext, nonce, nil)
}

// DecryptWithAAD decrypts ciphertext encrypted with matching aad using the provided 12-byte nonce.
func (v *Vault) DecryptWithAAD(ciphertext, nonce, aad []byte) ([]byte, error) {
	if v == nil || v.aead == nil {
		return nil, ErrVaultClosed
	}
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}
	plaintext, err := v.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
