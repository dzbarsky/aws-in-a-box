package s3

import (
	"aws-in-a-box/atomicfile"
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
)

func bucketsPath(dir string) string {
	return filepath.Join(dir, "buckets.gob")
}

func multipartUploadsPath(dir string) string {
	return filepath.Join(dir, "multipartUploads.gob")
}

func persist(data any, path string) error {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return err
	}
	_, err = atomicfile.Write(path, buf, 0600)
	return err
}

func load(data any, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	dec := gob.NewDecoder(f)
	return dec.Decode(data)
}

func (s *S3) persistMetadata() error {
	if s.metadataDir == "" {
		return nil
	}

	err := persist(s.buckets, bucketsPath(s.metadataDir))
	if err != nil {
		return err
	}
	err = persist(s.multipartUploads, multipartUploadsPath(s.metadataDir))
	if err != nil {
		return err
	}
	return nil
}

func loadMetadata(
	dir string,
	buckets map[string]*Bucket,
	multipartUploads map[string]*MultipartUpload,
) error {
	err := load(&buckets, bucketsPath(dir))
	if err != nil {
		return err
	}
	err = load(&multipartUploads, multipartUploadsPath(dir))
	if err != nil {
		return err
	}
	return nil
}
