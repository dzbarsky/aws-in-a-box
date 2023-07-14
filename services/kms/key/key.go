package key

import (
	"encoding/binary"

	"golang.org/x/exp/maps"
)

type Key struct {
	id      string
	enabled bool
	tags    map[string]string

	key *aesKey
}

func (k Key) Id() string {
	return k.id
}

func (k Key) Enabled() bool {
	return k.enabled
}

func (k *Key) Tags() map[string]string {
	return maps.Clone(k.tags)
}

func (k *Key) SetEnabled(enabled bool) {
	k.enabled = enabled
}

func (k *Key) SetTags(tags map[string]string) {
	for tagKey, tagValue := range tags {
		k.tags[tagKey] = tagValue
	}
}

func (k *Key) DeleteTags(tags []string) {
	for _, tag := range tags {
		delete(k.tags, tag)
	}
}

func NewAES(id string, tags map[string]string) *Key {
	return &Key{
		id:      id,
		tags:    tags,
		enabled: true,
		key:     newAesKey(),
	}
}

func (k *Key) Encrypt(
	plaintext []byte, context map[string]string,
) (
	[]byte, error,
) {
	ciphertext, version, err := k.key.Encrypt(plaintext, context)
	if err != nil {
		return nil, err
	}

	var packedBlob = []byte{uint8(len(k.id))}
	packedBlob = append(packedBlob, k.id...)
	packedBlob = binary.LittleEndian.AppendUint32(packedBlob, version)
	return append(packedBlob, ciphertext...), nil
}

func (k *Key) Decrypt(
	data []byte, context map[string]string,
) (
	[]byte, error,
) {
	version, data := binary.LittleEndian.Uint32(data[:4]), data[4:]
	return k.key.Decrypt(data, version, context)
}
