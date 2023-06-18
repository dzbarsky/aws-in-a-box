package kms

import (
	"bytes"
	"testing"
)

func newKMSWithKey() (*KMS, string) {
	k := New()
	output, err := k.CreateKey(CreateKeyInput{})
	if err != nil {
		panic(err)
	}

	return k, output.KeyMetadata.KeyId
}

func TestEncryptionContext(t *testing.T) {
	k, keyId := newKMSWithKey()

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	context := map[string]string{"k1": "v1", "k2": "v2"}
	encryptOutput, err := k.Encrypt(EncryptInput{
		KeyId:             keyId,
		EncryptionContext: context,
		Plaintext:         plaintext,
	})
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := encryptOutput.CiphertextBlob

	badContexts := []map[string]string{
		nil,
		{"k1": "v1"},
		{"k1": "v2"},
		{"k2": "v2"},
		{"k1": "v2", "k2": "v1"},
	}
	for _, context := range badContexts {
		_, err := k.Decrypt(DecryptInput{
			CiphertextBlob:    ciphertext,
			EncryptionContext: context,
		})
		if err == nil {
			t.Fatal("Expected error, bad context")
		}
	}

	goodContexts := []map[string]string{
		{"k1": "v1", "k2": "v2"},
		{"k2": "v2", "k1": "v1"},
	}
	for _, context := range goodContexts {
		decryptOutput, err := k.Decrypt(DecryptInput{
			CiphertextBlob:    ciphertext,
			EncryptionContext: context,
		})
		if err != nil {
			t.Fatal("Unexpected error, bad context")
		}
		if !bytes.Equal(plaintext, decryptOutput.Plaintext) {
			t.Fatalf("bad encryption result; got %v, want %v", decryptOutput.Plaintext, plaintext)
		}
	}
}
