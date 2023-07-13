package key

import (
	"reflect"
	"testing"
)

func TestSerialization(t *testing.T) {
	key, err := NewAES("", "keyId", map[string]string{"tag": "value"})
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
