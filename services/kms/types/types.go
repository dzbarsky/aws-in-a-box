package types

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
	EcdsaSHA256    SigningAlgorithm = "ECDSA_SHA_256"
	EcdsaSHA384    SigningAlgorithm = "ECDSA_SHA_384"
	EcdsaSHA512    SigningAlgorithm = "ECDSA_SHA_512"
)

type EncryptionAlgorithm string

const (
	SymmetricDefault EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	RsaSha1          EncryptionAlgorithm = "RSAES_OAEP_SHA_1"
	RsaSha256        EncryptionAlgorithm = "RSAES_OAEP_SHA_256"
)
