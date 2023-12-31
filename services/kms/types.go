package kms

import "aws-in-a-box/services/kms/types"

type CreateKeyInput struct {
	Description           string
	CustomerMasterKeySpec string
	KeySpec               string
	KeyUsage              string
	Tags                  []APITag
}

type CreateKeyOutput struct {
	KeyMetadata APIKeyMetadata
}

type DescribeKeyInput struct {
	KeyId string
}

type DescribeKeyOutput struct {
	KeyMetadata APIKeyMetadata
}

type CreateAliasInput struct {
	AliasName   string
	TargetKeyId string
}

type CreateAliasOutput struct{}

type DeleteAliasInput struct {
	AliasName string
}

type DeleteAliasOutput struct{}

type UpdateAliasInput struct {
	AliasName   string
	TargetKeyId string
}

type UpdateAliasOutput struct{}

type SignInput struct {
	KeyId            string
	Message          []byte
	SigningAlgorithm types.SigningAlgorithm
	MessageType      string
}

type SignOutput struct {
	KeyId            string
	Signature        []byte
	SigningAlgorithm types.SigningAlgorithm
}

type VerifyInput struct {
	KeyId            string
	Message          []byte
	MessageType      string
	Signature        []byte
	SigningAlgorithm types.SigningAlgorithm
}

type VerifyOutput struct {
	KeyId            string
	SignatureValid   bool
	SigningAlgorithm types.SigningAlgorithm
}

type ListAliasesInput struct {
	KeyId string
}

type ListAliasesOutput struct {
	Aliases []APIAliasListEntry
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_AliasListEntry.html
type APIAliasListEntry struct {
	AliasArn    string
	AliasName   string
	TargetKeyId string
}

type GenerateDataKeyInput struct {
	EncryptionContext map[string]string

	KeyId         string
	KeySpec       string
	NumberOfBytes int
}

type GenerateDataKeyOutput struct {
	CiphertextBlob []byte
	KeyId          string
	Plaintext      []byte
}

type GenerateDataKeyWithoutPlaintextInput = GenerateDataKeyInput

type GenerateDataKeyWithoutPlaintextOutput struct {
	CiphertextBlob []byte
	KeyId          string
}

type GenerateDataKeyPairInput struct {
	EncryptionContext map[string]string

	KeyId       string
	KeyPairSpec string
}

type GenerateDataKeyPairOutput struct {
	KeyId                    string
	KeyPairSpec              string
	PrivateKeyCiphertextBlob []byte
	PrivateKeyPlaintext      []byte
	PublicKey                []byte
}

type GenerateDataKeyPairWithoutPlaintextInput = GenerateDataKeyPairInput

type GenerateDataKeyPairWithoutPlaintextOutput struct {
	KeyId                    string
	KeyPairSpec              string
	PrivateKeyCiphertextBlob []byte
	PublicKey                []byte
}

type GenerateRandomInput struct {
	NumberOfBytes int
}

type GenerateRandomOutput struct {
	Plaintext []byte
}

type EncryptInput struct {
	EncryptionAlgorithm types.EncryptionAlgorithm
	EncryptionContext   map[string]string
	KeyId               string
	Plaintext           []byte
}

type EncryptOutput struct {
	CiphertextBlob      []byte
	EncryptionAlgorithm types.EncryptionAlgorithm
	KeyId               string
}

type GenerateMacInput struct {
	KeyId        string
	MacAlgorithm string
	Message      []byte
}

type GenerateMacOutput struct {
	KeyId        string
	MacAlgorithm string
	Mac          []byte
}

type VerifyMacInput struct {
	KeyId        string
	Mac          []byte
	MacAlgorithm string
	Message      []byte
}

type VerifyMacOutput struct {
	KeyId        string
	MacAlgorithm string
	MacValid     bool
}

type DecryptInput struct {
	CiphertextBlob      []byte
	EncryptionAlgorithm types.EncryptionAlgorithm
	EncryptionContext   map[string]string
	KeyId               string
}

type DecryptOutput struct {
	Plaintext           []byte
	EncryptionAlgorithm types.EncryptionAlgorithm
	KeyId               string
}

// https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html
type APIKeyMetadata struct {
	Arn                   string
	AWSAccountId          string
	CustomerMasterKeySpec string
	CreationDate          float64
	Description           string
	Enabled               bool
	EncryptionAlgorithms  []types.EncryptionAlgorithm
	KeyId                 string
	KeySpec               string
	KeyManager            string
	KeyState              string
	KeyUsage              types.Usage
	MacAlgorithms         []string
	MultiRegion           bool
	Origin                string
	SigningAlgorithms     []types.SigningAlgorithm
}

type UpdateKeyDescriptionInput struct {
	KeyId       string
	Description string
}

type UpdateKeyDescriptionOutput struct{}

type DisableKeyInput struct {
	KeyId string
}

type DisableKeyOutput struct{}

type EnableKeyInput struct {
	KeyId string
}

type EnableKeyOutput struct{}

type TagResourceInput struct {
	KeyId string
	Tags  []APITag
}

type APITag struct {
	TagKey   string
	TagValue string
}

type TagResourceOutput struct{}

type UntagResourceInput struct {
	KeyId string
	Tags  []string
}

type UntagResourceOutput struct{}

type ListResourceTagsInput struct {
	KeyId string
}

type ListResourceTagsOutput struct {
	Tags []APITag
}

type ListKeysInput struct{}

type ListKeysOutput struct {
	Keys []APIKey
}

type APIKey struct {
	KeyArn string
	KeyId  string
}

type ReEncryptInput struct {
	CiphertextBlob                 []byte
	DestinationEncryptionAlgorithm types.EncryptionAlgorithm
	DestinationEncryptionContext   map[string]string
	DestinationKeyId               string
	SourceKeyId                    string
	SourceEncryptionAlgorithm      types.EncryptionAlgorithm
	SourceEncryptionContext        map[string]string
}

type ReEncryptOutput struct {
	CiphertextBlob                 []byte
	DestinationEncryptionAlgorithm types.EncryptionAlgorithm
	KeyId                          string
	SourceEncryptionAlgorithm      types.EncryptionAlgorithm
	SourceKeyId                    string
}
