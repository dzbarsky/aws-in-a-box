package kms

import (
	"bytes"
	"strings"
	"testing"
)

func newKMSWithKey() (*KMS, string) {
	k := New(ServiceData{
		AWSAccountId: "12345",
		Region:       "us-east-1",
	})
	output, err := k.CreateKey(CreateKeyInput{})
	if err != nil {
		panic(err)
	}

	return k, output.KeyMetadata.KeyId
}

func TestEncryptionContext(t *testing.T) {
	k, keyId := newKMSWithKey()

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	context := map[string]string{"k1": "v1", "k2": "v2"}
	encryptOutput, err := k.Encrypt(EncryptInput{
		KeyId:             keyId,
		EncryptionContext: context,
		Plaintext:         plaintext,
	})
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := encryptOutput.CiphertextBlob

	badContexts := []map[string]string{
		nil,
		{"k1": "v1"},
		{"k1": "v2"},
		{"k2": "v2"},
		{"k1": "v2", "k2": "v1"},
	}
	for _, context := range badContexts {
		_, err := k.Decrypt(DecryptInput{
			CiphertextBlob:    ciphertext,
			EncryptionContext: context,
		})
		if err == nil {
			t.Fatal("Expected error, bad context")
		}
	}

	goodContexts := []map[string]string{
		{"k1": "v1", "k2": "v2"},
		{"k2": "v2", "k1": "v1"},
	}
	for _, context := range goodContexts {
		decryptOutput, err := k.Decrypt(DecryptInput{
			CiphertextBlob:    ciphertext,
			EncryptionContext: context,
		})
		if err != nil {
			t.Fatal("Unexpected error, bad context")
		}
		if !bytes.Equal(plaintext, decryptOutput.Plaintext) {
			t.Fatalf("bad encryption result; got %v, want %v", decryptOutput.Plaintext, plaintext)
		}
	}
}

func TestGenerateDataKey(t *testing.T) {
	k, keyId := newKMSWithKey()

	generateOutput, err := k.GenerateDataKey(GenerateDataKeyInput{
		NumberOfBytes: 256,
		KeyId:         keyId,
	})
	if err != nil {
		t.Fatal(err)
	}

	decryptOutput, err := k.Decrypt(DecryptInput{
		CiphertextBlob: generateOutput.CiphertextBlob,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(generateOutput.Plaintext, generateOutput.Plaintext) {
		t.Fatalf("bad encryption result; got %v, want %v", decryptOutput.Plaintext, generateOutput.Plaintext)
	}
}

func TestAliasCreateDelete(t *testing.T) {
	k, keyId := newKMSWithKey()

	output, err := k.ListAliases(ListAliasesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Aliases) != 0 {
		t.Fatal(output.Aliases)
	}

	_, err = k.CreateAlias(CreateAliasInput{
		AliasName:   "alias/short",
		TargetKeyId: keyId,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, aliasInput := range []ListAliasesInput{{}, {KeyId: keyId}} {
		output, err = k.ListAliases(aliasInput)
		if err != nil {
			t.Fatal(err)
		}
		if len(output.Aliases) != 1 {
			t.Fatal(output.Aliases)
		}
		alias := output.Aliases[0]
		if alias.AliasName != "alias/short" {
			t.Fatal(alias.AliasName)
		}
		if alias.TargetKeyId != keyId {
			t.Fatal(alias.TargetKeyId)
		}
		// TODO(zbarsky): fix ARN handling
		if alias.AliasArn != "arn:aws:kms:us-east-1:12345:key/"+keyId {
			t.Fatal(alias.AliasArn)
		}
	}

	output, err = k.ListAliases(ListAliasesInput{KeyId: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Aliases) != 0 {
		t.Fatal(output.Aliases)
	}

	_, err = k.DeleteAlias(DeleteAliasInput{
		AliasName: "alias/short",
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err = k.ListAliases(ListAliasesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Aliases) != 0 {
		t.Fatal(output.Aliases)
	}

	_, err = k.DeleteAlias(DeleteAliasInput{
		AliasName: "alias/short",
	})
	if err == nil {
		t.Fatal("Cannot delete missing alias")
	}
}

func TestAliasNaming(t *testing.T) {
	k, keyId := newKMSWithKey()

	_, err := k.CreateAlias(CreateAliasInput{
		AliasName:   "short",
		TargetKeyId: keyId,
	})
	if err == nil {
		t.Fatal("Illegal alias name")
	}

	_, err = k.CreateAlias(CreateAliasInput{
		AliasName:   "alias/short",
		TargetKeyId: keyId,
	})
	if err != nil {
		t.Fatal("Legal alias name")
	}

	_, err = k.CreateAlias(CreateAliasInput{
		AliasName:   "alias/aws",
		TargetKeyId: keyId,
	})
	if err != nil {
		t.Fatal("Legal alias name")
	}

	_, err = k.CreateAlias(CreateAliasInput{
		AliasName:   "alias/aws/short",
		TargetKeyId: keyId,
	})
	if err == nil {
		t.Fatal("Reserved alias name")
	}

	_, err = k.CreateAlias(CreateAliasInput{
		AliasName:   "alias/short" + strings.Repeat("long", 100),
		TargetKeyId: keyId,
	})
	if err == nil {
		t.Fatal("Long alias name")
	}

	_, err = k.CreateAlias(CreateAliasInput{
		AliasName:   "alias/short$",
		TargetKeyId: keyId,
	})
	if err == nil {
		t.Fatal("Bad character, illegal alias name")
	}
}
