package key

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"

	"aws-in-a-box/services/kms/types"
)

type rsaKey struct {
	key *rsa.PrivateKey
}

func newRsaKey(bits int) (rsaKey, error) {
	pkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return rsaKey{}, err
	}

	return rsaKey{
		key: pkey,
	}, nil
}

func (k rsaKey) Sign(
	digest []byte, algorithm types.SigningAlgorithm,
) (
	[]byte, error,
) {
	if len(digest) != k.key.Size() {
		return nil, errors.New("bad length")
	}

	var hasher crypto.Hash
	switch algorithm {
	case types.RsaPssSHA256, types.RsaPkcs1SHA256:
		hasher = crypto.SHA256
	case types.RsaPssSHA384, types.RsaPkcs1SHA384:
		hasher = crypto.SHA384
	case types.RsaPssSHA512, types.RsaPkcs1SHA512:
		hasher = crypto.SHA512
	default:
		return nil, InvalidSigningAlgorithm{}
	}

	switch algorithm {
	case types.RsaPssSHA256, types.RsaPssSHA384, types.RsaPssSHA512:
		return rsa.SignPSS(rand.Reader, k.key, hasher, digest, nil)
	case types.RsaPkcs1SHA256, types.RsaPkcs1SHA384, types.RsaPkcs1SHA512:
		return rsa.SignPKCS1v15(rand.Reader, k.key, hasher, digest)
	default:
		return nil, InvalidSigningAlgorithm{}
	}
}

func (k rsaKey) Verify(
	digest []byte,
	signature []byte,
	algorithm types.SigningAlgorithm,
) error {
	if len(digest) != k.key.Size() {
		return errors.New("bad length")
	}

	var hasher crypto.Hash
	switch algorithm {
	case types.RsaPssSHA256, types.RsaPkcs1SHA256:
		hasher = crypto.SHA256
	case types.RsaPssSHA384, types.RsaPkcs1SHA384:
		hasher = crypto.SHA384
	case types.RsaPssSHA512, types.RsaPkcs1SHA512:
		hasher = crypto.SHA512
	default:
		return InvalidSigningAlgorithm{}
	}

	switch algorithm {
	case types.RsaPssSHA256, types.RsaPssSHA384, types.RsaPssSHA512:
		return rsa.VerifyPSS(&k.key.PublicKey, hasher, digest, signature, nil)
	case types.RsaPkcs1SHA256, types.RsaPkcs1SHA384, types.RsaPkcs1SHA512:
		return rsa.VerifyPKCS1v15(&k.key.PublicKey, hasher, digest, signature)
	default:
		return InvalidSigningAlgorithm{}
	}
}

func (k rsaKey) Encrypt(
	plaintext []byte, algorithm types.EncryptionAlgorithm,
) ([]byte, error) {
	var hasher hash.Hash
	switch algorithm {
	case types.RsaSha1:
		hasher = sha1.New()
	case types.RsaSha256:
		hasher = sha256.New()
	default:
		return nil, errors.New("unknown encryption algorithm")
	}

	return rsa.EncryptOAEP(hasher, rand.Reader, &k.key.PublicKey, plaintext, nil)
}

func (k rsaKey) Decrypt(
	ciphertext []byte, algorithm types.EncryptionAlgorithm,
) ([]byte, error) {
	var hasher hash.Hash
	switch algorithm {
	case types.RsaSha1:
		hasher = sha1.New()
	case types.RsaSha256:
		hasher = sha256.New()
	default:
		return nil, errors.New("unknown encryption algorithm")
	}

	return rsa.DecryptOAEP(hasher, rand.Reader, k.key, ciphertext, nil)
}
