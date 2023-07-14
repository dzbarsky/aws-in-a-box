package s3

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"aws-in-a-box/awserrors"
)

type Object struct {
	Data        []byte
	ContentType string

	Tagging string

	ServerSideEncryption string
	SSECustomerAlgorithm string
	SSECustomerKey       string
	SSEKMSKeyId          string
}

type Bucket struct {
	objects map[string]Object
}

type S3 struct {
	mu      sync.Mutex
	buckets map[string]*Bucket
}

func New() *S3 {
	return &S3{
		buckets: make(map[string]*Bucket),
	}
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func (s *S3) CreateBucket(input CreateBucketInput) (*CreateBucketOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.buckets[input.Bucket]
	if ok {
		return nil, awserrors.XXX_TODO("bucket already exists")
	}

	s.buckets[input.Bucket] = &Bucket{
		objects: make(map[string]Object),
	}

	return &CreateBucketOutput{
		Location: "/" + input.Bucket,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
func (s *S3) GetObject(bucket string, key string) (*Object, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	object, ok := b.objects[key]
	if !ok {
		return nil, awserrors.XXX_TODO("no item")
	}

	return &object, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
func (s *S3) PutObject(bucket string, key string, data []byte, header http.Header) *awserrors.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return awserrors.XXX_TODO("no bucket")
	}

	b.objects[key] = Object{
		Data:        data,
		ContentType: header.Get("Content-Type"),

		Tagging:              header.Get("x-amz-tagging"),
		ServerSideEncryption: header.Get("x-amz-server-side-encryption"),
		SSEKMSKeyId:          header.Get("x-amz-server-side-encryption-aws-kms-key-id"),
		SSECustomerAlgorithm: header.Get("x-amz-server-side-encryption-customer-algorithm"),
		SSECustomerKey:       header.Get("x-amz-server-side-encryption-customer-key"),
	}
	return nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
func (s *S3) CopyObject(bucket string, key string, header http.Header) (*CopyObjectOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "/bucket/path/to/key"
	copySource, err := url.PathUnescape(header.Get("x-amz-copy-source"))
	if err != nil {
		return nil, awserrors.XXX_TODO(err.Error())
	}
	parts := strings.SplitN(copySource, "/", 3)
	sourceBucket := parts[1]
	sourceKey := parts[2]

	b, ok := s.buckets[sourceBucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	object, ok := b.objects[sourceKey]
	if !ok {
		return nil, awserrors.XXX_TODO("no source item")
	}

	metadataDirective := header.Get("x-amz-metadata-directive")
	if metadataDirective == "REPLACE" {
		// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html for full list
		object.ContentType = header.Get("Content-Type")
		object.ServerSideEncryption = header.Get("x-amz-server-side-encryption")
		object.SSEKMSKeyId = header.Get("x-amz-server-side-encryption-aws-kms-key-id")
		object.SSECustomerAlgorithm = header.Get("x-amz-server-side-encryption-customer-algorithm")
		object.SSECustomerKey = header.Get("x-amz-server-side-encryption-customer-key")
	}

	taggingDirective := header.Get("x-amz-tagging-directive")
	if taggingDirective == "REPLACE" {
		object.Tagging = header.Get("x-amz-tagging")
	}

	destBucket, ok := s.buckets[bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	destBucket.objects[key] = object
	// TODO: should probably compute this elsewhere
	hash := md5.Sum(object.Data)
	return &CopyObjectOutput{
		// TODO: Complete guess on format
		LastModified: time.Now().UTC().Format(time.RFC3339Nano),
		ETag:         hex.EncodeToString(hash[:]),
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
func (s *S3) DeleteObject(bucket string, key string) *awserrors.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return awserrors.XXX_TODO("no bucket")
	}

	_, ok = b.objects[key]
	if !ok {
		return awserrors.XXX_TODO("no item")
	}

	delete(b.objects, key)
	return nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html
func (s *S3) GetObjectTagging(bucket string, key string) (*GetObjectTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	object, ok := b.objects[key]
	if !ok {
		return nil, awserrors.XXX_TODO("no item")
	}

	tagging := &GetObjectTaggingOutput{}
	for _, kv := range strings.Split(object.Tagging, "&") {
		kv := strings.Split(kv, "=")
		if len(kv) != 2 {
			return nil, awserrors.XXX_TODO("invalid tagging")
		}
		tagging.Tagging.TagSet.Tag = append(tagging.Tagging.TagSet.Tag, APITag{
			Key:   kv[0],
			Value: kv[1],
		})
	}
	return tagging, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html
func (s *S3) PutObjectTagging(input PutObjectTaggingInput) (*PutObjectTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	object, ok := b.objects[input.Key]
	if !ok {
		return nil, awserrors.XXX_TODO("no item")
	}

	tagging := strings.Builder{}
	for i, tag := range input.Tagging.TagSet.Tag {
		tagging.WriteString(tag.Key)
		tagging.WriteRune('=')
		tagging.WriteString(tag.Value)
		if i != len(input.Tagging.TagSet.Tag)-1 {
			tagging.WriteRune(',')
		}
	}
	object.Tagging = tagging.String()

	return nil, nil
}
