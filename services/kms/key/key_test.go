package key

import (
	"reflect"
	"testing"
)

func TestSerializationAES(t *testing.T) {
	key, err := NewAES("", EncryptDecrypt, "keyId", map[string]string{"tag": "value"})
	if err != nil {
		t.Fatal(err)
	}

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
}

func TestSerializationRSA(t *testing.T) {
	key, err := NewRSA("", SignVerify, 2048, "keyId", map[string]string{"tag": "value"})
	if err != nil {
		t.Fatal(err)
	}

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
}
