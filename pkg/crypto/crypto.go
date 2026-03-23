package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

type Encryptor struct {
	aead cipher.AEAD
}

func NewEncryptor(masterKey string) (*Encryptor, error) {
	if masterKey == "" {
		return nil, fmt.Errorf("master key is required")
	}

	sum := sha256.Sum256([]byte(masterKey))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AEAD failed: %w", err)
	}

	return &Encryptor{aead: aead}, nil
}

func (e *Encryptor) EncryptString(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	encrypted, err := e.EncryptBytes([]byte(plain))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (e *Encryptor) DecryptString(cipherText string) (string, error) {
	if cipherText == "" {
		return "", nil
	}
	payload, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext failed: %w", err)
	}
	plain, err := e.DecryptBytes(payload)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (e *Encryptor) EncryptBytes(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}

	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce failed: %w", err)
	}

	return e.aead.Seal(nonce, nonce, plain, nil), nil
}

func (e *Encryptor) DecryptBytes(cipherText []byte) ([]byte, error) {
	if len(cipherText) == 0 {
		return nil, nil
	}
	if len(cipherText) < e.aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := cipherText[:e.aead.NonceSize()]
	payload := cipherText[e.aead.NonceSize():]
	plain, err := e.aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext failed: %w", err)
	}
	return plain, nil
}
