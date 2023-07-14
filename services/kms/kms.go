package kms

import (
	"aws-in-a-box/arn"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"

	"aws-in-a-box/awserrors"
	"aws-in-a-box/services/kms/key"
)

type KeyId = string

type KMS struct {
	arnGenerator arn.Generator
	persistDir   string

	mu sync.Mutex

	// The keys here do not include the "alias/" prefix
	aliases map[string]KeyId
	keys    map[KeyId]*key.Key
}

func New(arnGenerator arn.Generator, persistDir string) (*KMS, error) {
	keys := make(map[KeyId]*key.Key)

	if persistDir != "" {
		persistDir = filepath.Join(persistDir, "kms")
		err := os.MkdirAll(persistDir, 0700)
		if err != nil {
			return nil, err
		}

		files, err := os.ReadDir(persistDir)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			name := file.Name()
			fullPath := filepath.Join(persistDir, name)
			if strings.HasSuffix(name, ".tmp") {
				os.Remove(fullPath)
			} else if strings.HasSuffix(name, ".json") {
				key, err := key.NewFromFile(fullPath)
				if err != nil {
					return nil, err
				}
				keys[key.Id()] = key
			}
		}
	}

	return &KMS{
		arnGenerator: arnGenerator,
		persistDir:   persistDir,
		aliases:      make(map[string]KeyId),
		keys:         keys,
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
func (k *KMS) CreateKey(input CreateKeyInput) (*CreateKeyOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	keyId := uuid.Must(uuid.NewV4()).String()

	for _, t := range input.Tags {
		if !isValidTagKey(t.TagKey) || !isValidTagValue(t.TagValue) {
			return nil, TagException("")
		}
	}

	tags := fromAPITags(input.Tags)

	keySpec := input.KeySpec
	if keySpec == "" {
		keySpec = input.CustomerMasterKeySpec
	}

	switch keySpec {
	case "", "SYMMETRIC_DEFAULT":
		persistPath := ""
		if k.persistDir != "" {
			persistPath = filepath.Join(k.persistDir, keyId+".json")
		}
		k.keys[keyId] = key.NewAES(persistPath, keyId, tags)
	case "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512":
		return nil, UnsupportedOperationException("")
	case "RSA_2048", "RSA_3072", "RSA_4096":
		return nil, UnsupportedOperationException("")
	case "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521":
		return nil, UnsupportedOperationException("")
	default:
		// "ECC_SECG_P256K1", "SM2":
		return nil, UnsupportedOperationException("")
	}

	return &CreateKeyOutput{
		KeyMetadata: APIKeyMetadata{
			Arn:   k.arnGenerator.Generate("kms", "key", keyId),
			KeyId: keyId,
		},
	}, nil
}

func (k *KMS) lockedGetKey(keyId string) *key.Key {
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
			return nil
		}
	}

	return k.keys[keyId]
}

var aliasNameRe = regexp.MustCompile("^[a-zA-Z0-9/_-]+$")

// https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html
func (k *KMS) CreateAlias(input CreateAliasInput) (*CreateAliasOutput, *awserrors.Error) {
	if !strings.HasPrefix(input.AliasName, "alias/") {
		return nil, InvalidAliasNameException("")
	}

	if strings.HasPrefix(input.AliasName, "alias/aws/") {
		return nil, InvalidAliasNameException("")
	}

	if len(input.AliasName) > 256 {
		return nil, InvalidAliasNameException("")
	}

	if !aliasNameRe.MatchString(input.AliasName) {
		return nil, InvalidAliasNameException("")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(input.TargetKeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	aliasName := strings.TrimPrefix(input.AliasName, "alias/")
	if _, ok := k.aliases[aliasName]; ok {
		return nil, AlreadyExistsException("")
	}

	k.aliases[aliasName] = key.Id()
	return nil, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html
func (k *KMS) DeleteAlias(input DeleteAliasInput) (*DeleteAliasOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	// TODO: handle alias not starting with "alias/"
	aliasName := strings.TrimPrefix(input.AliasName, "alias/")
	if _, ok := k.aliases[aliasName]; !ok {
		return nil, NotFoundException("")
	}

	delete(k.aliases, aliasName)
	return nil, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html
func (k *KMS) ListAliases(input ListAliasesInput) (*ListAliasesOutput, *awserrors.Error) {
	output := &ListAliasesOutput{}

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
func (k *KMS) GenerateDataKey(input GenerateDataKeyInput) (*GenerateDataKeyOutput, *awserrors.Error) {
	numberOfBytes := input.NumberOfBytes
	if numberOfBytes < 0 || numberOfBytes > 1024 {
		return nil, XXXTodoException("Invalid number of bytes value")
	}
	if numberOfBytes == 0 {
		switch input.KeySpec {
		case "AES_256":
			numberOfBytes = 32
		case "AES_128":
			numberOfBytes = 16
		case "":
			return nil, InvalidParameterCombination("Must specify either KeySpec or NumberOfBytes")
		default:
			return nil, XXXTodoException("Invalid value for KeySpec")
		}
	}

	dataKey := make([]byte, numberOfBytes)
	rand.Read(dataKey)

	k.mu.Lock()
	defer k.mu.Unlock()
	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	if !key.Enabled() {
		return nil, DisabledException("")
	}

	// TODO: check for AES key when we have non-AES support
	encryptedDataKey, err := key.Encrypt(dataKey, input.EncryptionContext)
	if err != nil {
		return nil, KMSInternalException(err.Error())
	}

	return &GenerateDataKeyOutput{
		KeyId:          key.Id(),
		Plaintext:      dataKey,
		CiphertextBlob: encryptedDataKey,
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
func (k *KMS) GenerateDataKeyWithoutPlaintext(
	input GenerateDataKeyWithoutPlaintextInput,
) (*GenerateDataKeyWithoutPlaintextOutput, *awserrors.Error) {
	output, err := k.GenerateDataKey(input)
	if err != nil {
		return nil, err
	}

	return &GenerateDataKeyWithoutPlaintextOutput{
		CiphertextBlob: output.CiphertextBlob,
		KeyId:          output.KeyId,
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
func (k *KMS) Encrypt(input EncryptInput) (*EncryptOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(input.Plaintext) == 0 || len(input.Plaintext) > 4096 {
		return nil, XXXTodoException("bad length")
	}

	if input.EncryptionAlgorithm == "" {
		input.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	if !key.Enabled() {
		return nil, DisabledException("")
	}

	ciphertext, err := key.Encrypt(input.Plaintext, input.EncryptionContext)
	if err != nil {
		return nil, KMSInternalException(err.Error())
	}

	return &EncryptOutput{
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: input.EncryptionAlgorithm,
		KeyId:               key.Id(),
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
func (k *KMS) Decrypt(input DecryptInput) (*DecryptOutput, *awserrors.Error) {
	if input.EncryptionAlgorithm == "" {
		input.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	// Opposite of Key.Encrypt
	data := input.CiphertextBlob
	if len(data) == 0 {
		return nil, InvalidCiphertextException("")
	}

	keyArnLen, data := uint8(data[0]), data[1:]
	if len(data) < 4+int(keyArnLen) {
		return nil, InvalidCiphertextException("")
	}
	keyArn, data := string(data[:keyArnLen]), data[keyArnLen:]

	if input.KeyId != "" {
		keyArn = input.KeyId
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(keyArn)
	if key == nil {
		return nil, NotFoundException("")
	}

	if !key.Enabled() {
		return nil, DisabledException("")
	}

	plaintext, err := key.Decrypt(data, input.EncryptionContext)
	if err != nil {
		return nil, InvalidCiphertextException(err.Error())
	}

	return &DecryptOutput{
		Plaintext:           plaintext,
		EncryptionAlgorithm: input.EncryptionAlgorithm,
		KeyId:               key.Id(),
	}, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html
func (k *KMS) DisableKey(input DisableKeyInput) (*DisableKeyOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	err := key.SetEnabled(false)
	if err != nil {
		return nil, KMSInternalException(err.Error())
	}
	return nil, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKey.html
func (k *KMS) EnableKey(input EnableKeyInput) (*EnableKeyOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	err := key.SetEnabled(true)
	if err != nil {
		return nil, KMSInternalException(err.Error())
	}
	return nil, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_TagResource.html
func (k *KMS) TagResource(input TagResourceInput) (*TagResourceOutput, *awserrors.Error) {
	if strings.HasPrefix(input.KeyId, "alias/") {
		return nil, XXXTodoException("Cannot tag alias")
	}

	for _, t := range input.Tags {
		if !isValidTagKey(t.TagKey) || !isValidTagValue(t.TagValue) {
			return nil, TagException("")
		}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	err := key.SetTags(fromAPITags(input.Tags))
	if err != nil {
		return nil, KMSInternalException(err.Error())
	}
	return nil, nil
}

func fromAPITags(apiTags []APITag) map[string]string {
	tags := make(map[string]string, len(apiTags))
	for _, t := range apiTags {
		tags[t.TagKey] = t.TagValue
	}
	return tags
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_UntagResource.html
func (k *KMS) UntagResource(input UntagResourceInput) (*UntagResourceOutput, *awserrors.Error) {
	if strings.HasPrefix(input.KeyId, "alias/") {
		return nil, XXXTodoException("Cannot tag alias")
	}

	for _, tagKey := range input.Tags {
		if !isValidTagKey(tagKey) {
			return nil, TagException("")
		}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	err := key.DeleteTags(input.Tags)
	if err != nil {
		return nil, KMSInternalException(err.Error())
	}
	return nil, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_ListResourceTags.html
func (k *KMS) ListResourceTags(input ListResourceTagsInput) (*ListResourceTagsOutput, *awserrors.Error) {
	if strings.HasPrefix(input.KeyId, "alias/") {
		return nil, XXXTodoException("Cannot tag alias")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	key := k.lockedGetKey(input.KeyId)
	if key == nil {
		return nil, NotFoundException("")
	}

	output := &ListResourceTagsOutput{}
	for tagKey, tagValue := range key.Tags() {
		output.Tags = append(output.Tags, APITag{
			TagKey:   tagKey,
			TagValue: tagValue,
		})
	}

	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html
func (k *KMS) ListKeys(input ListKeysInput) (*ListKeysOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	output := &ListKeysOutput{}
	for _, key := range k.keys {
		output.Keys = append(output.Keys, APIKey{
			KeyId:  key.Id(),
			KeyArn: k.arnGenerator.Generate("kms", "key", key.Id()),
		})
	}

	return output, nil
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html
func (k *KMS) ReEncrypt(input ReEncryptInput) (*ReEncryptOutput, *awserrors.Error) {
	decryptOutput, err := k.Decrypt(DecryptInput{
		CiphertextBlob:      input.CiphertextBlob,
		EncryptionAlgorithm: input.SourceEncryptionAlgorithm,
		EncryptionContext:   input.SourceEncryptionContext,
		KeyId:               input.SourceKeyId,
	})
	if err != nil {
		return nil, err
	}
	encryptOutput, err := k.Encrypt(EncryptInput{
		EncryptionAlgorithm: input.DestinationEncryptionAlgorithm,
		EncryptionContext:   input.DestinationEncryptionContext,
		KeyId:               input.DestinationKeyId,
		Plaintext:           decryptOutput.Plaintext,
	})
	if err != nil {
		return nil, err
	}

	return &ReEncryptOutput{
		CiphertextBlob:                 encryptOutput.CiphertextBlob,
		DestinationEncryptionAlgorithm: encryptOutput.EncryptionAlgorithm,
		KeyId:                          encryptOutput.KeyId,
		SourceEncryptionAlgorithm:      decryptOutput.EncryptionAlgorithm,
		SourceKeyId:                    decryptOutput.KeyId,
	}, nil
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
