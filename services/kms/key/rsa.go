package key

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"
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
	digest []byte, algorithm SigningAlgorithm,
) (
	[]byte, error,
) {
	if len(digest) != k.key.Size() {
		return nil, errors.New("bad length")
	}

	var hasher crypto.Hash
	switch algorithm {
	case RsaPssSHA256, RsaPkcs1SHA256:
		hasher = crypto.SHA256
	case RsaPssSHA384, RsaPkcs1SHA384:
		hasher = crypto.SHA384
	case RsaPssSHA512, RsaPkcs1SHA512:
		hasher = crypto.SHA512
	default:
		return nil, InvalidSigningAlgorithm{}
	}

	switch algorithm {
	case RsaPssSHA256, RsaPssSHA384, RsaPssSHA512:
		return rsa.SignPSS(rand.Reader, k.key, hasher, digest, nil)
	case RsaPkcs1SHA256, RsaPkcs1SHA384, RsaPkcs1SHA512:
		return rsa.SignPKCS1v15(rand.Reader, k.key, hasher, digest)
	default:
		return nil, InvalidSigningAlgorithm{}
	}
}

func (k rsaKey) Verify(
	digest []byte,
	signature []byte,
	algorithm SigningAlgorithm,
) error {
	if len(digest) != k.key.Size() {
		return errors.New("bad length")
	}

	var hasher crypto.Hash
	switch algorithm {
	case RsaPssSHA256, RsaPkcs1SHA256:
		hasher = crypto.SHA256
	case RsaPssSHA384, RsaPkcs1SHA384:
		hasher = crypto.SHA384
	case RsaPssSHA512, RsaPkcs1SHA512:
		hasher = crypto.SHA512
	default:
		return InvalidSigningAlgorithm{}
	}

	switch algorithm {
	case RsaPssSHA256, RsaPssSHA384, RsaPssSHA512:
		return rsa.VerifyPSS(&k.key.PublicKey, hasher, digest, signature, nil)
	case RsaPkcs1SHA256, RsaPkcs1SHA384, RsaPkcs1SHA512:
		return rsa.VerifyPKCS1v15(&k.key.PublicKey, hasher, digest, signature)
	default:
		return InvalidSigningAlgorithm{}
	}
}

func (k rsaKey) Encrypt(
	plaintext []byte, algorithm string,
) ([]byte, error) {
	var hasher hash.Hash
	switch algorithm {
	case "RSAES_OAEP_SHA_1":
		hasher = sha1.New()
	case "RSAES_OAEP_SHA_256":
		hasher = sha256.New()
	default:
		return nil, errors.New("unknown encryption algorithm")
	}

	return rsa.EncryptOAEP(hasher, rand.Reader, &k.key.PublicKey, plaintext, nil)
}

func (k rsaKey) Decrypt(
	ciphertext []byte, algorithm string,
) ([]byte, error) {
	var hasher hash.Hash
	switch algorithm {
	case "RSAES_OAEP_SHA_1":
		hasher = sha1.New()
	case "RSAES_OAEP_SHA_256":
		hasher = sha256.New()
	default:
		return nil, errors.New("unknown encryption algorithm")
	}

	return rsa.DecryptOAEP(hasher, rand.Reader, k.key, ciphertext, nil)
}
