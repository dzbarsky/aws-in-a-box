package key

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"hash"
	"os"

	"golang.org/x/exp/maps"

	"aws-in-a-box/atomicfile"
)

type Usage string

const (
	EncryptDecrypt    Usage = "ENCRYPT_DECRYPT"
	GenerateVerifyMAC Usage = "GENERATE_VERIFY_MAC"
	SignVerify        Usage = "SIGN_VERIFY"
)

type SigningAlgorithm string

const (
	RsaPssSHA256   SigningAlgorithm = "RSASSA_PSS_SHA_256"
	RsaPssSHA384   SigningAlgorithm = "RSASSA_PSS_SHA_384"
	RsaPssSHA512   SigningAlgorithm = "RSASSA_PSS_SHA_512"
	RsaPkcs1SHA256 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	RsaPkcs1SHA384 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	RsaPkcs1SHA512 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"
)

type Key struct {
	// If empty, no persistence
	persistPath string

	// immutable
	id    string
	usage Usage

	// mutable
	description string
	enabled     bool
	tags        map[string]string

	// variants
	aesKey  aesKey
	rsaKey  rsaKey
	hmacKey hmacKey
}

func (k Key) IsAES() bool {
	return len(k.aesKey.backingKeys) > 0
}

func (k Key) Id() string {
	return k.id
}

func (k Key) Enabled() bool {
	return k.enabled
}

func (k Key) Usage() Usage {
	return k.usage
}

func (k Key) Description() string {
	return k.description
}

func (k *Key) Tags() map[string]string {
	return maps.Clone(k.tags)
}

func (k *Key) SetEnabled(enabled bool) error {
	k.enabled = enabled
	return k.persist()
}

func (k *Key) SetDescription(description string) error {
	k.description = description
	return k.persist()
}

func (k *Key) SetTags(tags map[string]string) error {
	for tagKey, tagValue := range tags {
		k.tags[tagKey] = tagValue
	}
	return k.persist()
}

func (k *Key) DeleteTags(tags []string) error {
	for _, tag := range tags {
		delete(k.tags, tag)
	}
	return k.persist()
}

func (k *Key) persist() error {
	if k.persistPath == "" {
		return nil
	}
	data, err := k.serialize()
	if err != nil {
		return err
	}
	_, err = atomicfile.Write(k.persistPath, bytes.NewBuffer(data), 0600)
	return err
}

type serializableKey struct {
	Id          string
	Usage       Usage
	Enabled     bool
	Description string
	Tags        map[string]string
	AesKeys     [][32]byte
	RsaKey      *rsa.PrivateKey
	HmacKey     []byte
}

func (k *Key) serialize() ([]byte, error) {
	return json.Marshal(serializableKey{
		Id:          k.id,
		Usage:       k.usage,
		Enabled:     k.enabled,
		Description: k.description,
		Tags:        k.tags,
		AesKeys:     k.aesKey.backingKeys,
		RsaKey:      k.rsaKey.key,
		HmacKey:     k.hmacKey.key,
	})
}

type Options struct {
	PersistPath string
	Usage       Usage
	Id          string
	Description string
	Tags        map[string]string
}

func (o Options) makeKey() *Key {
	return &Key{
		persistPath: o.PersistPath,
		id:          o.Id,
		usage:       o.Usage,
		description: o.Description,
		tags:        o.Tags,
		enabled:     true,
	}
}

func NewAES(options Options) (*Key, error) {
	k := options.makeKey()
	k.aesKey = newAesKey()

	err := k.persist()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func NewRSA(options Options, bits int) (*Key, error) {
	rsaKey, err := newRsaKey(bits)
	if err != nil {
		return nil, err
	}

	k := options.makeKey()
	k.rsaKey = rsaKey

	err = k.persist()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func NewHMAC(options Options, bytes int) (*Key, error) {
	k := options.makeKey()
	k.hmacKey = newHmacKey(bytes)

	err := k.persist()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func NewFromFile(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := newFromData(data)
	if err != nil {
		return nil, err
	}
	key.persistPath = path
	return key, nil
}

func newFromData(data []byte) (*Key, error) {
	var key serializableKey
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}

	// Not stricly necessary, but helps the serialization round-trip test
	if key.RsaKey != nil {
		key.RsaKey.Precompute()
	}

	return &Key{
		id:          key.Id,
		enabled:     key.Enabled,
		usage:       key.Usage,
		tags:        key.Tags,
		description: key.Description,
		aesKey:      aesKey{backingKeys: key.AesKeys},
		rsaKey:      rsaKey{key: key.RsaKey},
		hmacKey:     hmacKey{key: key.HmacKey},
	}, nil
}

func (k *Key) Encrypt(
	plaintext []byte,
	algorithm string,
	context map[string]string,
) (
	[]byte, error,
) {
	if k.rsaKey.key != nil {
		return k.rsaKey.Encrypt(plaintext, algorithm)
	}
	ciphertext, version, err := k.aesKey.Encrypt(plaintext, context)
	if err != nil {
		return nil, err
	}

	var packedBlob = []byte{uint8(len(k.id))}
	packedBlob = append(packedBlob, k.id...)
	packedBlob = binary.LittleEndian.AppendUint32(packedBlob, version)
	return append(packedBlob, ciphertext...), nil
}

func (k *Key) Decrypt(
	data []byte, algorithm string, context map[string]string,
) (
	[]byte, error,
) {
	if k.rsaKey.key != nil {
		return k.rsaKey.Decrypt(data, algorithm)
	}
	version, data := binary.LittleEndian.Uint32(data[:4]), data[4:]
	return k.aesKey.Decrypt(data, version, context)
}

func (k *Key) Sign(
	digest []byte,
	algorithm SigningAlgorithm,
) (
	[]byte, error,
) {
	return k.rsaKey.Sign(digest, algorithm)
}

func (k *Key) Verify(
	digest []byte,
	signature []byte,
	algorithm SigningAlgorithm,
) error {
	return k.rsaKey.Verify(digest, signature, algorithm)
}

func (k *Key) GenerateMac(
	hasher func() hash.Hash, message []byte,
) []byte {
	return k.hmacKey.GenerateMac(hasher, message)
}

func (k *Key) VerifyMac(
	hasher func() hash.Hash,
	message []byte,
	mac []byte,
) bool {
	return hmac.Equal(mac, k.hmacKey.GenerateMac(hasher, message))
}
