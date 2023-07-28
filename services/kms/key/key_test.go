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

	options := Options{
		// Not correct, but fine for this test
		Usage:       EncryptDecrypt,
		Id:          "keyId",
		Description: "",
		Tags:        map[string]string{"tag": "value"},
	}
	tests := map[string]*Key{
		"AES":  must(NewAES(options)),
		"RSA":  must(NewRSA(options, 2048)),
		"HMAC": must(NewHMAC(options, 256)),
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
