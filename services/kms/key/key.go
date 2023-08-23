package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"maps"
	"os"
	"slices"
	"time"

	"aws-in-a-box/atomicfile"
	"aws-in-a-box/services/kms/types"
)

type metadata struct {
	// Immutable
	Id                   string
	CreationDate         float64
	KeySpec              string
	Usage                types.Usage
	EncryptionAlgorithms []types.EncryptionAlgorithm
	MacAlgorithms        []string
	SigningAlgorithms    []types.SigningAlgorithm

	// Mutable
	Description string
	Enabled     bool
	Tags        map[string]string
}

type Key struct {
	// If empty, no persistence
	persistPath string

	metadata metadata
	// variants
	aesKey  aesKey
	rsaKey  rsaKey
	hmacKey hmacKey
	eccKey  eccKey
}

func (k Key) IsAES() bool {
	return len(k.aesKey.backingKeys) > 0
}

func (k Key) IsRSA() bool {
	return k.rsaKey.key != nil
}

func (k Key) IsHMAC() bool {
	return len(k.hmacKey.key) > 0
}

func (k Key) IsECC() bool {
	return k.eccKey.key != nil
}

func (k Key) IsAsymmetric() bool {
	return k.IsRSA() || k.IsECC()
}

func (k Key) Id() string {
	return k.metadata.Id
}

func (k Key) Enabled() bool {
	return k.metadata.Enabled
}

func (k Key) KeySpec() string {
	return k.metadata.KeySpec
}

func (k Key) KeyState() string {
	// TODO: more key states
	if k.metadata.Enabled {
		return "Enabled"
	} else {
		return "Disabled"
	}
}

func (k Key) Usage() types.Usage {
	return k.metadata.Usage
}

func (k Key) CreationDate() float64 {
	return k.metadata.CreationDate
}

func (k Key) Description() string {
	return k.metadata.Description
}

func (k *Key) Tags() map[string]string {
	return maps.Clone(k.metadata.Tags)
}

func (k *Key) EncryptionAlgorithms() []types.EncryptionAlgorithm {
	return slices.Clone(k.metadata.EncryptionAlgorithms)
}

func (k *Key) SigningAlgorithms() []types.SigningAlgorithm {
	return slices.Clone(k.metadata.SigningAlgorithms)
}

func (k *Key) MacAlgorithms() []string {
	return slices.Clone(k.metadata.MacAlgorithms)
}

func (k *Key) SetEnabled(enabled bool) error {
	k.metadata.Enabled = enabled
	return k.persist()
}

func (k *Key) SetDescription(description string) error {
	k.metadata.Description = description
	return k.persist()
}

func (k *Key) SetTags(tags map[string]string) error {
	for tagKey, tagValue := range tags {
		k.metadata.Tags[tagKey] = tagValue
	}
	return k.persist()
}

func (k *Key) DeleteTags(tags []string) error {
	for _, tag := range tags {
		delete(k.metadata.Tags, tag)
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
	Metadata metadata

	AesKeys [][32]byte
	RsaKey  *rsa.PrivateKey
	HmacKey []byte
	// Note: ecdsa Keys don't serialize nicely, see https://github.com/golang/go/issues/33564
	// So instead, we use the PKCS8 format. Note that this means the parsed keys used the generic
	// curves rather than the specialized ones, which is a performance hit.
	EccKey []byte
}

func (k *Key) serialize() ([]byte, error) {
	key := serializableKey{
		Metadata: k.metadata,
		AesKeys:  k.aesKey.backingKeys,
		RsaKey:   k.rsaKey.key,
		HmacKey:  k.hmacKey.key,
	}

	if k.eccKey.key != nil {
		data, err := x509.MarshalPKCS8PrivateKey(k.eccKey.key)
		if err != nil {
			return nil, err
		}
		key.EccKey = data
	}

	return json.Marshal(key)
}

type Options struct {
	PersistPath  string
	CreationDate time.Time
	Description  string
	Id           string
	KeySpec      string
	Tags         map[string]string
	Usage        types.Usage
}

func (o Options) makeKey() *Key {
	return &Key{
		persistPath: o.PersistPath,
		metadata: metadata{
			CreationDate: float64(o.CreationDate.UnixMilli()) / 1000,
			Description:  o.Description,
			Id:           o.Id,
			KeySpec:      o.KeySpec,
			Tags:         o.Tags,
			Usage:        o.Usage,

			Enabled: true,
		},
	}
}

func NewAES(options Options) (*Key, error) {
	k := options.makeKey()
	k.aesKey = newAesKey()
	k.metadata.EncryptionAlgorithms = []types.EncryptionAlgorithm{types.SymmetricDefault}

	err := k.persist()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func shaForBytes(bytes int) string {
	switch bytes {
	case 224:
		return "HMAC_SHA_224"
	case 256:
		return "HMAC_SHA_256"
	case 384:
		return "HMAC_SHA_384"
	case 512:
		return "HMAC_SHA_512"
	default:
		panic(fmt.Sprintf("bad bytes: %v", bytes))
	}
}

func NewRSA(options Options, bits int) (*Key, error) {
	rsaKey, err := newRsaKey(bits)
	if err != nil {
		return nil, err
	}

	k := options.makeKey()
	k.rsaKey = rsaKey
	if options.Usage == types.EncryptDecrypt {
		k.metadata.EncryptionAlgorithms = []types.EncryptionAlgorithm{
			types.RsaSha1, types.RsaSha256,
		}
	} else {
		k.metadata.SigningAlgorithms = []types.SigningAlgorithm{
			types.RsaPkcs1SHA256,
			types.RsaPkcs1SHA384,
			types.RsaPkcs1SHA512,
			types.RsaPssSHA256,
			types.RsaPssSHA384,
			types.RsaPssSHA512,
		}
	}

	err = k.persist()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func NewHMAC(options Options, bytes int) (*Key, error) {
	k := options.makeKey()
	k.hmacKey = newHmacKey(bytes)
	k.metadata.MacAlgorithms = []string{shaForBytes(bytes)}

	err := k.persist()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func NewECC(options Options, bytes string) (*Key, error) {
	k := options.makeKey()

	var curve elliptic.Curve
	switch bytes {
	case "256":
		curve = elliptic.P256()
		k.metadata.SigningAlgorithms = []types.SigningAlgorithm{
			types.EcdsaSHA256,
		}
	case "384":
		curve = elliptic.P384()
		k.metadata.SigningAlgorithms = []types.SigningAlgorithm{
			types.EcdsaSHA384,
		}
	case "521":
		curve = elliptic.P521()
		k.metadata.SigningAlgorithms = []types.SigningAlgorithm{
			types.EcdsaSHA512,
		}
	default:
		return nil, errors.New("unknown size")
	}

	eccKey, err := newECCKey(curve)
	if err != nil {
		return nil, err
	}
	k.eccKey = eccKey

	err = k.persist()
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

	k := &Key{
		metadata: key.Metadata,
		aesKey:   aesKey{backingKeys: key.AesKeys},
		rsaKey:   rsaKey{key: key.RsaKey},
		hmacKey:  hmacKey{key: key.HmacKey},
	}

	if len(key.EccKey) > 0 {
		pkey, err := x509.ParsePKCS8PrivateKey(key.EccKey)
		if err != nil {
			return nil, err
		}
		k.eccKey = eccKey{pkey.(*ecdsa.PrivateKey)}
	}

	return k, nil
}

var ErrBadAlgorithm = errors.New("Bad algorithm")

func (k *Key) Encrypt(
	plaintext []byte,
	algorithm types.EncryptionAlgorithm,
	context map[string]string,
) (
	[]byte, error,
) {
	if !slices.Contains(k.metadata.EncryptionAlgorithms, algorithm) {
		return nil, ErrBadAlgorithm
	}

	if k.IsRSA() {
		return k.rsaKey.Encrypt(plaintext, algorithm)
	}
	ciphertext, version, err := k.aesKey.Encrypt(plaintext, context)
	if err != nil {
		return nil, err
	}

	var packedBlob = []byte{uint8(len(k.metadata.Id))}
	packedBlob = append(packedBlob, k.metadata.Id...)
	packedBlob = binary.LittleEndian.AppendUint32(packedBlob, version)
	return append(packedBlob, ciphertext...), nil
}

func (k *Key) Decrypt(
	data []byte,
	algorithm types.EncryptionAlgorithm,
	context map[string]string,
) (
	[]byte, error,
) {
	if !slices.Contains(k.metadata.EncryptionAlgorithms, algorithm) {
		return nil, ErrBadAlgorithm
	}

	if k.IsRSA() {
		return k.rsaKey.Decrypt(data, algorithm)
	}
	version, data := binary.LittleEndian.Uint32(data[:4]), data[4:]
	return k.aesKey.Decrypt(data, version, context)
}

func (k *Key) Sign(
	digest []byte,
	algorithm types.SigningAlgorithm,
) (
	[]byte, error,
) {
	if !slices.Contains(k.metadata.SigningAlgorithms, algorithm) {
		return nil, ErrBadAlgorithm
	}

	if k.IsRSA() {
		return k.rsaKey.Sign(digest, algorithm)
	} else {
		return k.eccKey.Sign(digest)
	}
}

func (k *Key) Verify(
	digest []byte,
	signature []byte,
	algorithm types.SigningAlgorithm,
) (bool, error) {
	if !slices.Contains(k.metadata.SigningAlgorithms, algorithm) {
		return false, ErrBadAlgorithm
	}

	if k.IsRSA() {
		err := k.rsaKey.Verify(digest, signature, algorithm)
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return true, err
	} else {
		return k.eccKey.Verify(digest, signature), nil
	}
}

func (k *Key) GenerateMac(
	algorithm string, message []byte,
) ([]byte, error) {
	if !slices.Contains(k.metadata.MacAlgorithms, algorithm) {
		return nil, ErrBadAlgorithm
	}

	var hasher func() hash.Hash
	switch algorithm {
	case "HMAC_SHA_224":
		hasher = sha256.New224
	case "HMAC_SHA_256":
		hasher = sha256.New
	case "HMAC_SHA_384":
		hasher = sha512.New384
	case "HMAC_SHA_512":
		hasher = sha512.New
	default:
		return nil, ErrBadAlgorithm
	}

	return k.hmacKey.GenerateMac(hasher, message), nil
}
