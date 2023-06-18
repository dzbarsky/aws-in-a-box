package kms

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
)

type KeyId = string

type KeyWithMetadata struct {
	Id  KeyId
	Key *AESKey
}

func (k *KeyWithMetadata) Encrypt(
	plaintext []byte, context map[string]string,
) (
	[]byte, error,
) {
	ciphertext, version, err := k.Key.Encrypt(plaintext, context)
	if err != nil {
		return nil, err
	}

	var packedBlob = []byte{uint8(len(k.Id))}
	packedBlob = append(packedBlob, k.Id...)
	packedBlob = binary.LittleEndian.AppendUint32(packedBlob, version)
	return append(packedBlob, ciphertext...), nil
}

type ServiceData struct {
	Region       string
	AWSAccountId string
}

type KMS struct {
	serviceData ServiceData

	mu sync.Mutex

	aliases map[string]KeyId
	keys    map[KeyId]*KeyWithMetadata
}

func New(serviceData ServiceData) *KMS {
	return &KMS{
		serviceData: serviceData,
		aliases:     make(map[string]KeyId),
		keys:        make(map[KeyId]*KeyWithMetadata),
	}
}

func (k *KMS) arnPrefix() string {
	return "arn:aws:kms:" + k.serviceData.Region + ":" + k.serviceData.AWSAccountId + ":"
}

func (k *KMS) arnFromKeyId(keyId string) string {
	return k.arnPrefix() + "key/" + keyId
}

func keyIdFromArn(arn string) KeyId {
	return KeyId(strings.Split(arn, "/")[1])
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
func (k *KMS) CreateKey(input CreateKeyInput) (CreateKeyOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	var output CreateKeyOutput

	keyId := uuid.Must(uuid.NewV4()).String()

	var key *AESKey

	switch input.KeySpec {
	case "", "SYMMETRIC_DEFAULT":
		key = newAesKey()
	case "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512":
		return output, errors.New("UnsupportedOperationException")
	case "RSA_2048", "RSA_3072", "RSA_4096":
		return output, errors.New("UnsupportedOperationException")
	case "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521":
		return output, errors.New("UnsupportedOperationException")
	default:
		// "ECC_SECG_P256K1", "SM2":
		return output, errors.New("UnsupportedOperationException")
	}

	k.keys[keyId] = &KeyWithMetadata{
		Id:  keyId,
		Key: key,
	}
	return CreateKeyOutput{
		KeyMetadata: APIKeyMetadata{
			Arn:   k.arnFromKeyId(keyId),
			KeyId: keyId,
		},
	}, nil
}

func (k *KMS) lockedGetKey(keyId string) (*KeyWithMetadata, error) {
	if strings.HasPrefix(keyId, "alias/") {
		var ok bool
		keyId, ok = k.aliases[keyId[6:]]
		if !ok {
			return nil, errors.New("NotFoundException")
		}
	}

	if strings.HasPrefix(keyId, "arn") {
		keyId = keyIdFromArn(keyId)
	}

	key, ok := k.keys[keyId]
	if !ok {
		return nil, errors.New("NotFoundException")
	}
	return key, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html
func (k *KMS) CreateAlias(input CreateAliasInput) (CreateAliasOutput, error) {
	var output CreateAliasOutput

	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.TargetKeyId)
	if err != nil {
		return output, err
	}

	if _, ok := k.aliases[input.AliasName]; ok {
		return output, errors.New("AlreadyExistsException")
	}

	k.aliases[input.AliasName] = key.Id
	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html
func (k *KMS) DeleteAlias(input DeleteAliasInput) (DeleteAliasOutput, error) {
	var output DeleteAliasOutput

	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.aliases[input.AliasName]; !ok {
		return output, errors.New("NotFoundException")
	}

	delete(k.aliases, input.AliasName)
	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html
func (k *KMS) ListAliases(input ListAliasesInput) (ListAliasesOutput, error) {
	var output ListAliasesOutput

	k.mu.Lock()
	defer k.mu.Unlock()

	for alias, target := range k.aliases {
		// TODO: handle ARN
		if input.KeyId == "" || input.KeyId == target {
			output.Aliases = append(output.Aliases, APIAliasListEntry{
				AliasName:   alias,
				AliasArn:    k.arnFromKeyId(target),
				TargetKeyId: target,
			})
		}
	}

	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
func (k *KMS) GenerateDataKey(input GenerateDataKeyInput) (GenerateDataKeyOutput, error) {
	var output GenerateDataKeyOutput

	numberOfBytes := input.NumberOfBytes
	if numberOfBytes < 0 || numberOfBytes > 1024 {
		return output, errors.New("Invalid number of bytes value")
	}
	if numberOfBytes == 0 {
		switch input.KeySpec {
		case "AES_256":
			numberOfBytes = 32
		case "AES_128":
			numberOfBytes = 16
		case "":
			return output, errors.New("Must specify either KeySpec or NumberOfBytes")
		default:
			return output, errors.New("Invalid value for KeySpec")
		}
	}

	dataKey := make([]byte, numberOfBytes)
	rand.Read(dataKey)

	k.mu.Lock()
	defer k.mu.Unlock()
	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return output, err
	}

	// TODO: check for AES key when we have non-AES support
	encryptedDataKey, err := key.Encrypt(dataKey, input.EncryptionContext)
	if err != nil {
		return output, err
	}

	return GenerateDataKeyOutput{
		KeyId:          key.Id,
		Plaintext:      dataKey,
		CiphertextBlob: encryptedDataKey,
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
func (k *KMS) GenerateDataKeyWithoutPlaintext(
	input GenerateDataKeyWithoutPlaintextInput,
) (GenerateDataKeyWithoutPlaintextOutput, error) {
	output, err := k.GenerateDataKey(input)
	return GenerateDataKeyWithoutPlaintextOutput{
		CiphertextBlob: output.CiphertextBlob,
		KeyId:          output.KeyId,
	}, err
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
func (k *KMS) Encrypt(input EncryptInput) (EncryptOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	var output EncryptOutput

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return output, err
	}

	if len(input.Plaintext) == 0 || len(input.Plaintext) > 4096 {
		return output, errors.New("bad length")
	}

	if input.EncryptionAlgorithm == "" {
		input.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	ciphertext, err := key.Encrypt(input.Plaintext, input.EncryptionContext)
	if err != nil {
		return output, err
	}

	return EncryptOutput{
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: input.EncryptionAlgorithm,
		KeyId:               key.Id,
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
func (k *KMS) Decrypt(input DecryptInput) (DecryptOutput, error) {
	if input.EncryptionAlgorithm == "" {
		input.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	// Opposite of Key.Encrypt
	data := input.CiphertextBlob
	keyArnLen, data := uint8(data[0]), data[1:]
	keyArn, data := string(data[:keyArnLen]), data[keyArnLen:]
	version, data := binary.LittleEndian.Uint32(data[:4]), data[4:]

	if input.KeyId != "" {
		keyArn = input.KeyId
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(keyArn)
	if err != nil {
		return DecryptOutput{}, err
	}

	plaintext, err := key.Key.Decrypt(data, version, input.EncryptionContext)
	if err != nil {
		return DecryptOutput{}, err
	}

	return DecryptOutput{
		Plaintext:           plaintext,
		EncryptionAlgorithm: input.EncryptionAlgorithm,
		KeyId:               key.Id,
	}, nil
}
