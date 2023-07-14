package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
)

type aesKey struct {
	// For now, we just have 1. Should enable key rotation.
	backingKeys [][32]byte
}

func newAesKey() *aesKey {
	var backingKey [32]byte
	rand.Read(backingKey[:])

	return &aesKey{
		backingKeys: [][32]byte{backingKey},
	}
}

func (a *aesKey) Encrypt(
	plaintext []byte, context map[string]string,
) (
	[]byte, uint32, error,
) {
	// TODO: proper version support
	version := uint32(0)
	key := a.backingKeys[version]

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return nil, 0, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	rand.Read(nonce)

	// Note, the only requirement is that you need the same context to retrieve
	// the data, and that key order does not matter. json.Marshal fits the bill.
	marshaledContext, err := json.Marshal(context)
	if err != nil {
		return nil, 0, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, marshaledContext)

	return append(nonce, ciphertext...), version, nil
}

func (a *aesKey) Decrypt(
	ciphertext []byte, version uint32, context map[string]string,
) (
	[]byte, error,
) {
	if version >= uint32(len(a.backingKeys)) {
		return nil, errors.New("bad version")
	}

	key := a.backingKeys[version]
	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	nonce := ciphertext[:nonceSize]

	// Note, the only requirement is that you need the same context to retrieve
	// the data, and that key order does not matter. json.Marshal fits the bill.
	marshaledContext, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext[nonceSize:], marshaledContext)
}
