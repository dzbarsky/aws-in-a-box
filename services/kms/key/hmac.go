package key

import (
	"crypto/hmac"
	"crypto/rand"
	"hash"
)

type hmacKey struct {
	key []byte
}

func newHmacKey(bytes int) hmacKey {
	key := make([]byte, bytes)
	rand.Read(key)
	return hmacKey{key}
}

func (h hmacKey) GenerateMac(
	hasher func() hash.Hash, message []byte,
) []byte {
	return hmac.New(hasher, h.key).Sum(message)
}
