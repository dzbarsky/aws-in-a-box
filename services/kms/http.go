package kms

import (
	"log/slog"

	"aws-in-a-box/http"
)

const service = "TrentService"

func (k *KMS) RegisterHTTPHandlers(logger *slog.Logger, methodRegistry http.Registry) {
	http.Register(logger, methodRegistry, service, "CreateAlias", k.CreateAlias)
	http.Register(logger, methodRegistry, service, "CreateKey", k.CreateKey)
	http.Register(logger, methodRegistry, service, "Decrypt", k.Decrypt)
	http.Register(logger, methodRegistry, service, "DeleteAlias", k.DeleteAlias)
	http.Register(logger, methodRegistry, service, "DescribeKey", k.DescribeKey)
	http.Register(logger, methodRegistry, service, "DisableKey", k.DisableKey)
	http.Register(logger, methodRegistry, service, "EnableKey", k.EnableKey)
	http.Register(logger, methodRegistry, service, "Encrypt", k.Encrypt)
	http.Register(logger, methodRegistry, service, "GenerateDataKey", k.GenerateDataKey)
	http.Register(logger, methodRegistry, service, "GenerateDataKeyPair", k.GenerateDataKeyPair)
	http.Register(logger, methodRegistry, service, "GenerateDataKeyWithoutPlaintext", k.GenerateDataKeyWithoutPlaintext)
	http.Register(logger, methodRegistry, service, "GenerateDataKeyPairWithoutPlaintext", k.GenerateDataKeyPairWithoutPlaintext)
	http.Register(logger, methodRegistry, service, "GenerateMac", k.GenerateMac)
	http.Register(logger, methodRegistry, service, "GenerateRandom", k.GenerateRandom)
	http.Register(logger, methodRegistry, service, "ListAliases", k.ListAliases)
	http.Register(logger, methodRegistry, service, "ListKeys", k.ListKeys)
	http.Register(logger, methodRegistry, service, "ListResourceTags", k.ListResourceTags)
	http.Register(logger, methodRegistry, service, "ReEncrypt", k.ReEncrypt)
	http.Register(logger, methodRegistry, service, "Sign", k.Sign)
	http.Register(logger, methodRegistry, service, "TagResource", k.TagResource)
	http.Register(logger, methodRegistry, service, "UntagResource", k.UntagResource)
	http.Register(logger, methodRegistry, service, "UpdateAlias", k.UpdateAlias)
	http.Register(logger, methodRegistry, service, "UpdateKeyDescription", k.UpdateKeyDescription)
	http.Register(logger, methodRegistry, service, "Verify", k.Verify)
	http.Register(logger, methodRegistry, service, "VerifyMac", k.VerifyMac)
}
