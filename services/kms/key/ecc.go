package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

type eccKey struct {
	key *ecdsa.PrivateKey
}

func newECCKey(curve elliptic.Curve) (eccKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	return eccKey{key}, err
}

func (k eccKey) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, k.key, digest)
}

func (k eccKey) Verify(digest []byte, signature []byte) bool {
	return ecdsa.VerifyASN1(&k.key.PublicKey, digest, signature)
}
