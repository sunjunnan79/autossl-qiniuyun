package crypto

import "testing"

func TestEncryptorRoundTrip(t *testing.T) {
	encryptor, err := NewEncryptor("top-secret")
	if err != nil {
		t.Fatalf("NewEncryptor returned error: %v", err)
	}

	cipherText, err := encryptor.EncryptString("hello")
	if err != nil {
		t.Fatalf("EncryptString returned error: %v", err)
	}
	if cipherText == "hello" {
		t.Fatalf("expected ciphertext to differ from plaintext")
	}

	plain, err := encryptor.DecryptString(cipherText)
	if err != nil {
		t.Fatalf("DecryptString returned error: %v", err)
	}
	if plain != "hello" {
		t.Fatalf("expected plaintext hello, got %q", plain)
	}
}

func TestEncryptorRejectsWrongKey(t *testing.T) {
	encryptor, err := NewEncryptor("key-a")
	if err != nil {
		t.Fatalf("NewEncryptor returned error: %v", err)
	}
	cipherText, err := encryptor.EncryptString("hello")
	if err != nil {
		t.Fatalf("EncryptString returned error: %v", err)
	}

	other, err := NewEncryptor("key-b")
	if err != nil {
		t.Fatalf("NewEncryptor returned error: %v", err)
	}
	if _, err := other.DecryptString(cipherText); err == nil {
		t.Fatalf("expected decrypt with wrong key to fail")
	}
}
