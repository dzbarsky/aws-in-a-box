package kms

import (
	"aws-in-a-box/arn"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
)

type KeyId = string

type KeyWithMetadata struct {
	Id       KeyId
	Disabled bool
	Tags     map[string]string

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

type KMS struct {
	arnGenerator arn.Generator

	mu sync.Mutex

	// The keys here do not include the "alias/" prefix
	aliases map[string]KeyId
	keys    map[KeyId]*KeyWithMetadata
}

func New(arnGenerator arn.Generator) *KMS {
	return &KMS{
		arnGenerator: arnGenerator,
		aliases:      make(map[string]KeyId),
		keys:         make(map[KeyId]*KeyWithMetadata),
	}
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
func (k *KMS) CreateKey(input CreateKeyInput) (CreateKeyOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	var output CreateKeyOutput

	keyId := uuid.Must(uuid.NewV4()).String()

	var aesKey *AESKey

	switch input.KeySpec {
	case "", "SYMMETRIC_DEFAULT":
		aesKey = newAesKey()
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

	key := &KeyWithMetadata{
		Id:  keyId,
		Key: aesKey,
	}

	for _, t := range input.Tags {
		if !isValidTagKey(t.TagKey) || !isValidTagValue(t.TagValue) {
			return output, errors.New("TagException")
		}
		key.Tags[t.TagKey] = t.TagValue
	}

	k.keys[keyId] = key

	return CreateKeyOutput{
		KeyMetadata: APIKeyMetadata{
			Arn:   k.arnGenerator.Generate("kms", "key", keyId),
			KeyId: keyId,
		},
	}, nil
}

func (k *KMS) lockedGetKey(keyId string) (*KeyWithMetadata, error) {
	// There are 4 possible ways to specify a key:
	// - Key ID: 1234abcd-12ab-34cd-56ef-1234567890ab
	// - Key ARN: arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
	// - Alias name: alias/ExampleAlias
	// - Alias ARN: arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias

	var isAlias bool
	if strings.HasPrefix(keyId, "arn:") {
		var resourceType string
		resourceType, keyId = arn.ExtractId(keyId)
		isAlias = resourceType == "alias"
	} else if strings.HasPrefix(keyId, "alias/") {
		_, keyId, isAlias = strings.Cut(keyId, "alias/")
	}

	if isAlias {
		var ok bool
		keyId, ok = k.aliases[keyId]
		if !ok {
			return nil, errors.New("NotFoundException")
		}
	}

	key, ok := k.keys[keyId]
	if !ok {
		return nil, errors.New("NotFoundException")
	}
	return key, nil
}

var aliasNameRe = regexp.MustCompile("^[a-zA-Z0-9/_-]+$")

// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html
func (k *KMS) CreateAlias(input CreateAliasInput) (CreateAliasOutput, error) {
	var output CreateAliasOutput

	if !strings.HasPrefix(input.AliasName, "alias/") {
		return output, errors.New("InvalidAliasNameException")
	}

	if strings.HasPrefix(input.AliasName, "alias/aws/") {
		return output, errors.New("InvalidAliasNameException")
	}

	if len(input.AliasName) > 256 {
		return output, errors.New("InvalidAliasNameException")
	}

	if !aliasNameRe.MatchString(input.AliasName) {
		return output, errors.New("InvalidAliasNameException")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.TargetKeyId)
	if err != nil {
		return output, err
	}

	aliasName := strings.TrimPrefix(input.AliasName, "alias/")
	if _, ok := k.aliases[aliasName]; ok {
		return output, errors.New("AlreadyExistsException")
	}

	k.aliases[aliasName] = key.Id
	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html
func (k *KMS) DeleteAlias(input DeleteAliasInput) (DeleteAliasOutput, error) {
	var output DeleteAliasOutput

	k.mu.Lock()
	defer k.mu.Unlock()

	// TODO: handle alias not starting with "alias/"
	aliasName := strings.TrimPrefix(input.AliasName, "alias/")
	if _, ok := k.aliases[aliasName]; !ok {
		return output, errors.New("NotFoundException")
	}

	delete(k.aliases, aliasName)
	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html
func (k *KMS) ListAliases(input ListAliasesInput) (ListAliasesOutput, error) {
	var output ListAliasesOutput

	k.mu.Lock()
	defer k.mu.Unlock()

	for alias, target := range k.aliases {
		if input.KeyId == "" || input.KeyId == target {
			output.Aliases = append(output.Aliases, APIAliasListEntry{
				AliasName:   "alias/" + alias,
				AliasArn:    k.arnGenerator.Generate("kms", "alias", alias),
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

	if key.Disabled {
		return output, errors.New("DisabledException")
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

	if len(input.Plaintext) == 0 || len(input.Plaintext) > 4096 {
		return output, errors.New("bad length")
	}

	if input.EncryptionAlgorithm == "" {
		input.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return output, err
	}

	if key.Disabled {
		return output, errors.New("DisabledException")
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

	if key.Disabled {
		return DecryptOutput{}, errors.New("DisabledException")
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

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html
func (k *KMS) DisableKey(input DisableKeyInput) (DisableKeyOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return DisableKeyOutput{}, err
	}

	key.Disabled = true
	return DisableKeyOutput{}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKey.html
func (k *KMS) EnableKey(input EnableKeyInput) (EnableKeyOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return EnableKeyOutput{}, err
	}

	key.Disabled = false
	return EnableKeyOutput{}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_TagResource.html
func (k *KMS) TagResource(input TagResourceInput) (TagResourceOutput, error) {
	if strings.HasPrefix(input.KeyId, "alias/") {
		return TagResourceOutput{}, errors.New("Cannot tag alias")
	}

	for _, t := range input.Tags {
		if !isValidTagKey(t.TagKey) || !isValidTagValue(t.TagValue) {
			return TagResourceOutput{}, errors.New("TagException")
		}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return TagResourceOutput{}, err
	}

	for _, t := range input.Tags {
		key.Tags[t.TagKey] = t.TagValue
	}

	return TagResourceOutput{}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_UntagResource.html
func (k *KMS) UntagResource(input UntagResourceInput) (UntagResourceOutput, error) {
	if strings.HasPrefix(input.KeyId, "alias/") {
		return UntagResourceOutput{}, errors.New("Cannot tag alias")
	}

	for _, tagKey := range input.Tags {
		if !isValidTagKey(tagKey) {
			return UntagResourceOutput{}, errors.New("TagException")
		}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return UntagResourceOutput{}, err
	}

	for _, tag := range input.Tags {
		delete(key.Tags, tag)
	}

	return UntagResourceOutput{}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_ListResourceTags.html
func (k *KMS) ListResourceTags(input ListResourceTagsInput) (ListResourceTagsOutput, error) {
	var output ListResourceTagsOutput
	if strings.HasPrefix(input.KeyId, "alias/") {
		return output, errors.New("Cannot tag alias")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key, err := k.lockedGetKey(input.KeyId)
	if err != nil {
		return output, err
	}

	for tagKey, tagValue := range key.Tags {
		output.Tags = append(output.Tags, APITag{
			TagKey:   tagKey,
			TagValue: tagValue,
		})
	}

	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html
func (k *KMS) ListKeys(input ListKeysInput) (ListKeysOutput, error) {
	var output ListKeysOutput

	k.mu.Lock()
	defer k.mu.Unlock()

	for _, key := range k.keys {
		output.Keys = append(output.Keys, APIKey{
			KeyId:  key.Id,
			KeyArn: k.arnGenerator.Generate("kms", "key", key.Id),
		})
	}

	return output, nil
}

func isValidTagKey(tagKey string) bool {
	if strings.HasPrefix(tagKey, "aws:") {
		return false
	}

	if len(tagKey) == 0 || len(tagKey) > 128 {
		return false
	}

	return true
}

func isValidTagValue(tagValue string) bool {
	if len(tagValue) == 0 || len(tagValue) > 256 {
		return false
	}

	return true
}
