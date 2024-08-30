package s3

import (
	"reflect"
	"strings"
	"testing"
)

var bucket = "test-bucket"

func TestPersist(t *testing.T) {
	tmpDir := t.TempDir()
	s3, err := New(Options{PersistDir: tmpDir})
	if err != nil {
		t.Fatal(err)
	}

	_, awserr := s3.CreateBucket(CreateBucketInput{
		Bucket: bucket,
	})
	if awserr != nil {
		t.Fatal(awserr)
	}

	kmsKey := "custom-kms-key"
	key := "test-key"
	kmsContext := "foo=bar"
	upload, awserr := s3.CreateMultipartUpload(CreateMultipartUploadInput{
		Bucket:                  bucket,
		Key:                     key,
		ServerSideEncryption:    "aws-kms",
		SSEKMSKeyId:             kmsKey,
		SSEKMSEncryptionContext: kmsContext,
		Tagging:                 "foo=bar",
	})
	if awserr != nil {
		t.Fatal(awserr)
	}
	id := upload.UploadId

	for i, s := range []string{"hello", " world"} {
		_, err := s3.UploadPart(UploadPartInput{
			PartNumber: i,
			Bucket:     bucket,
			Key:        key,
			UploadId:   id,
			Data:       strings.NewReader(s),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	_, awserr = s3.PutObject(PutObjectInput{
		Bucket:  bucket,
		Key:     key,
		Tagging: "key=value",
		Data:    strings.NewReader("hello"),
	})
	if awserr != nil {
		t.Fatal(awserr)
	}

	restoredS3, err := New(Options{PersistDir: tmpDir})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s3.multipartUploads, restoredS3.multipartUploads) {
		t.Fatal("wrong multipart uploads")
	}
	if !reflect.DeepEqual(s3.buckets, restoredS3.buckets) {
		t.Fatal("wrong buckets")
	}
}
