package key

import (
	"reflect"
	"testing"
)

func TestSerialization(t *testing.T) {
	must := func(key *Key, err error) *Key {
		if err != nil {
			t.Fatal(err)
		}
		return key
	}

	tests := map[string]*Key{
		"AES":  must(NewAES("", EncryptDecrypt, "keyId", map[string]string{"tag": "value"})),
		"RSA":  must(NewRSA("", SignVerify, 2048, "keyId", map[string]string{"tag": "value"})),
		"HMAC": must(NewHMAC("", GenerateVerifyMAC, 256, "keyId", map[string]string{"tag": "value"})),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := key.serialize()
			if err != nil {
				t.Fatal(err)
			}

			key2, err := newFromData(data)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(key, key2) {
				t.Fatalf("bad key; got %v, want %v", key2, key)
			}
		})
	}
}
