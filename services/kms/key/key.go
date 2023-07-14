package key

import (
	"encoding/binary"
	"encoding/json"
	"os"

	"golang.org/x/exp/maps"

	"aws-in-a-box/atomicfile"
)

type Key struct {
	// If empty, no persistence
	persistPath string

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

func (k *Key) SetEnabled(enabled bool) error {
	k.enabled = enabled
	return k.persist()
}

func (k *Key) SetTags(tags map[string]string) error {
	for tagKey, tagValue := range tags {
		k.tags[tagKey] = tagValue
	}
	return k.persist()
}

func (k *Key) DeleteTags(tags []string) error {
	for _, tag := range tags {
		delete(k.tags, tag)
	}
	return k.persist()
}

func (k *Key) persist() error {
	if k.persistPath == "" {
		return nil
	}
	data, err := k.serialize()
	if err != nil {
		return err
	}
	return atomicfile.Write(k.persistPath, data, 0600)
}

type serializableKey struct {
	Id      string
	Enabled bool
	Tags    map[string]string
	AesKeys [][32]byte
}

func (k *Key) serialize() ([]byte, error) {
	return json.Marshal(serializableKey{
		Id:      k.id,
		Enabled: k.enabled,
		Tags:    k.tags,
		AesKeys: k.key.backingKeys,
	})
}

func NewAES(persistPath string, id string, tags map[string]string) *Key {
	return &Key{
		persistPath: persistPath,
		id:          id,
		tags:        tags,
		enabled:     true,
		key:         newAesKey(),
	}
}

func NewFromFile(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := newFromData(data)
	if err != nil {
		return nil, err
	}
	key.persistPath = path
	return key, nil
}

func newFromData(data []byte) (*Key, error) {
	var key serializableKey
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}

	return &Key{
		id:      key.Id,
		enabled: key.Enabled,
		tags:    key.Tags,
		key: &aesKey{
			backingKeys: key.AesKeys,
		},
	}, nil
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
