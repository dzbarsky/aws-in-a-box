package kms

import "aws-in-a-box/http"

const service = "TrentService"

func (k *KMS) RegisterHTTPHandlers(methodRegistry http.Registry) {
	http.Register(methodRegistry, service, "CreateAlias", k.CreateAlias)
	http.Register(methodRegistry, service, "CreateKey", k.CreateKey)
	http.Register(methodRegistry, service, "Decrypt", k.Decrypt)
	http.Register(methodRegistry, service, "DeleteAlias", k.DeleteAlias)
	http.Register(methodRegistry, service, "DisableKey", k.DisableKey)
	http.Register(methodRegistry, service, "EnableKey", k.EnableKey)
	http.Register(methodRegistry, service, "Encrypt", k.Encrypt)
	http.Register(methodRegistry, service, "GenerateDataKey", k.GenerateDataKey)
	http.Register(methodRegistry, service, "GenerateDataKeyWithoutPlaintext", k.GenerateDataKeyWithoutPlaintext)
	http.Register(methodRegistry, service, "ListAliases", k.ListAliases)
	http.Register(methodRegistry, service, "ListKeys", k.ListKeys)
	http.Register(methodRegistry, service, "ListResourceTags", k.ListResourceTags)
	http.Register(methodRegistry, service, "ReEncrypt", k.ReEncrypt)
	http.Register(methodRegistry, service, "TagResource", k.TagResource)
	http.Register(methodRegistry, service, "UntagResource", k.UntagResource)
}
