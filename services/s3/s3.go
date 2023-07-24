package s3

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"

	"aws-in-a-box/atomicfile"
	"aws-in-a-box/awserrors"
)

type Object struct {
	MD5  []byte
	ETag string

	ContentType   string
	ContentLength int64
	Parts         []Part

	Tagging string

	ServerSideEncryption    string
	SSECustomerAlgorithm    string
	SSECustomerKey          string
	SSEKMSKeyId             string
	SSEKMSEncryptionContext string
}

type Bucket struct {
	objects map[string]*Object
	TagSet  TagSet
}

type UploadStatus int

const (
	UploadStatusInProgress UploadStatus = iota
	UploadStatusCompleted
	UploadStatusAborted
)

type multipartUpload struct {
	Status UploadStatus
	Bucket string
	Key    string
	Parts  map[int]Part
	// For metadata
	Object Object
}

type Part struct {
	Number int
	MD5    []byte
	Size   int64
}

type S3 struct {
	logger *slog.Logger

	// We need the address to generate location URLs.
	addr       string
	persistDir string

	mu               sync.Mutex
	buckets          map[string]*Bucket
	multipartUploads map[string]*multipartUpload
}

type Options struct {
	Logger     *slog.Logger
	Addr       string
	PersistDir string
}

func New(options Options) (*S3, error) {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}

	if options.PersistDir == "" {
		var err error
		options.PersistDir, err = os.MkdirTemp("", "aws-in-a-box-s3")
		if err != nil {
			return nil, err
		}
	} else {
		options.PersistDir = filepath.Join(options.PersistDir, "s3", "cas")
		err := os.MkdirAll(options.PersistDir, 0700)
		if err != nil {
			return nil, err
		}
	}

	return &S3{
		logger:           options.Logger,
		addr:             options.Addr,
		persistDir:       options.PersistDir,
		buckets:          make(map[string]*Bucket),
		multipartUploads: make(map[string]*multipartUpload),
	}, nil
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
		objects: make(map[string]*Object),
	}

	return &CreateBucketOutput{
		Location: "/" + input.Bucket,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
func (s *S3) HeadBucket(input HeadBucketInput) (*HeadBucketOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NotFound()
	}

	return &HeadBucketOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
func (s *S3) DeleteBucket(input DeleteBucketInput) (*Response204, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if ok {
		return nil, awserrors.XXX_TODO("bucket already exists")
	}

	if len(b.objects) != 0 {
		return nil, awserrors.XXX_TODO("bucket must be empty")
	}

	delete(s.buckets, input.Bucket)
	return response204, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
func (s *S3) GetObject(input GetObjectInput) (*GetObjectOutput, *awserrors.Error) {
	return s.getObject(input, true)
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
func (s *S3) HeadObject(input GetObjectInput) (*GetObjectOutput, *awserrors.Error) {
	return s.getObject(input, false)
}

func (s *S3) getObject(input GetObjectInput, includeBody bool) (*GetObjectOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NotFound()
	}

	object, ok := b.objects[input.Key]
	if !ok {
		return nil, NotFound()
	}

	output := &GetObjectOutput{
		ContentLength:        object.ContentLength,
		ETag:                 object.ETag,
		ContentType:          object.ContentType,
		ServerSideEncryption: object.ServerSideEncryption,
		SSECustomerAlgorithm: object.SSECustomerAlgorithm,
		SSECustomerKey:       object.SSECustomerKey,
		SSEKMSKeyId:          object.SSEKMSKeyId,
	}
	if includeBody {
		var md5s [][]byte
		if len(object.Parts) == 0 {
			md5s = [][]byte{object.MD5}
		} else {
			for _, part := range object.Parts {
				md5s = append(md5s, part.MD5)
			}
		}

		var readers []io.Reader
		for _, md5 := range md5s {
			f, err := os.Open(s.filepath(md5))
			if err != nil {
				return nil, awserrors.XXX_TODO(err.Error())
			}
			readers = append(readers, f)
		}
		output.Body = io.MultiReader(readers...)
	}
	return output, nil
}

func (s *S3) filepath(MD5 []byte) string {
	return filepath.Join(s.persistDir, hex.EncodeToString(MD5))
}

// drainReaderToMD5Store returns the MD5 and the number of bytes written
func (s *S3) drainReaderToMD5Store(r io.Reader) ([]byte, int64, error) {
	md5Writer := md5.New()
	tempPath := filepath.Join(s.persistDir, uuid.Must(uuid.NewV4()).String())
	n, err := atomicfile.Write(tempPath, io.TeeReader(r, md5Writer), 0666)
	if err != nil {
		return nil, 0, err
	}

	MD5 := md5Writer.Sum(nil)
	err = os.Rename(tempPath, s.filepath(MD5))
	if err != nil {
		return nil, 0, err
	}
	return MD5, n, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
func (s *S3) PutObject(input PutObjectInput) (*PutObjectOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	MD5, contentLength, err := s.drainReaderToMD5Store(input.Data)
	if err != nil {
		return nil, awserrors.XXX_TODO(err.Error())
	}

	object := &Object{
		MD5:           MD5,
		ETag:          hex.EncodeToString(MD5),
		ContentType:   input.ContentType,
		ContentLength: contentLength,

		Tagging:              input.Tagging,
		ServerSideEncryption: input.ServerSideEncryption,
		SSEKMSKeyId:          input.SSEKMSKeyId,
		SSECustomerAlgorithm: input.SSECustomerAlgorithm,
		SSECustomerKey:       input.SSECustomerKey,
	}
	b.objects[input.Key] = object

	return &PutObjectOutput{
		ETag:                    object.ETag,
		SSECustomerAlgorithm:    input.SSECustomerAlgorithm,
		SSEKMSKeyId:             input.SSEKMSKeyId,
		SSEKMSEncryptionContext: input.SSEKMSEncryptionContext,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
func (s *S3) CopyObject(input CopyObjectInput) (*CopyObjectOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// "/bucket/path/to/key"
	copySource, err := url.PathUnescape(input.CopySource)
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

	if input.MetadataDirective == "REPLACE" {
		// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html for full list
		object.ContentType = input.ContentType
		object.ServerSideEncryption = input.ServerSideEncryption
		object.SSEKMSKeyId = input.SSEKMSKeyId
		object.SSECustomerAlgorithm = input.SSECustomerAlgorithm
		object.SSECustomerKey = input.SSECustomerKey
	}

	if input.TaggingDirective == "REPLACE" {
		object.Tagging = input.Tagging
	}

	destBucket, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	destBucket.objects[input.Key] = object
	return &CopyObjectOutput{
		// TODO: Complete guess on format
		LastModified: time.Now().UTC().Format(time.RFC3339Nano),
		ETag:         object.ETag,
	}, nil
}

func etag(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html
func (s *S3) DeleteObject(input DeleteObjectInput) (*DeleteObjectOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NotFound()
	}

	_, ok = b.objects[input.Key]
	if !ok {
		return nil, NotFound()
	}

	delete(b.objects, input.Key)
	return &DeleteObjectOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html
func (s *S3) DeleteObjects(input DeleteObjectsInput) (*DeleteObjectsOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		// Ensure the rest of the lookups will be misses
		b = &Bucket{
			objects: map[string]*Object{},
		}
	}

	output := &DeleteObjectsOutput{}
	for _, object := range input.Object {
		_, ok = b.objects[object.Key]
		if !ok {
			err := NotFound().Body
			output.Error = append(output.Error, DeleteObjectsError{
				Code:    err.Type,
				Key:     object.Key,
				Message: err.Message,
			})
			continue
		}

		delete(b.objects, object.Key)
		if !input.Quiet {
			output.Deleted = append(output.Deleted, DeleteObjectsDeleted{
				Key: object.Key,
			})
		}
	}
	return output, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html
func (s *S3) GetObjectTagging(input GetObjectTaggingInput) (*GetObjectTaggingOutput, *awserrors.Error) {
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

	tagging := &GetObjectTaggingOutput{}
	for _, kv := range strings.Split(object.Tagging, "&") {
		kv := strings.Split(kv, "=")
		if len(kv) != 2 {
			return nil, awserrors.XXX_TODO("invalid tagging")
		}
		tagging.TagSet.Tag = append(tagging.TagSet.Tag, APITag{
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
	for i, tag := range input.TagSet.Tag {
		tagging.WriteString(tag.Key)
		tagging.WriteRune('=')
		tagging.WriteString(tag.Value)
		if i != len(input.TagSet.Tag)-1 {
			tagging.WriteRune(',')
		}
	}
	object.Tagging = tagging.String()

	return &PutObjectTaggingOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html
func (s *S3) DeleteObjectTagging(input DeleteObjectTaggingInput) (*Response204, *awserrors.Error) {
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
	object.Tagging = ""

	return response204, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html
func (s *S3) CreateMultipartUpload(input CreateMultipartUploadInput) (*CreateMultipartUploadOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	uploadId := base64.RawURLEncoding.EncodeToString(uuid.Must(uuid.NewV4()).Bytes())

	s.multipartUploads[uploadId] = &multipartUpload{
		Status: UploadStatusInProgress,
		Bucket: input.Bucket,
		Key:    input.Key,
		Parts:  make(map[int]Part),
		// Just for metadata
		Object: Object{
			ContentType:             input.ContentType,
			ServerSideEncryption:    input.ServerSideEncryption,
			SSEKMSKeyId:             input.SSEKMSKeyId,
			SSEKMSEncryptionContext: input.SSEKMSEncryptionContext,
		},
	}

	return &CreateMultipartUploadOutput{
		Bucket:   input.Bucket,
		Key:      input.Key,
		UploadId: uploadId,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html
func (s *S3) UploadPart(input UploadPartInput) (*UploadPartOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upload, ok := s.multipartUploads[input.UploadId]
	if !ok {
		return nil, awserrors.XXX_TODO("no upload")
	}

	if upload.Bucket != input.Bucket || upload.Key != input.Key {
		return nil, awserrors.XXX_TODO("wrong upload")
	}

	MD5, contentLength, err := s.drainReaderToMD5Store(input.Data)
	if err != nil {
		return nil, awserrors.XXX_TODO(err.Error())
	}

	upload.Parts[input.PartNumber] = Part{
		Number: input.PartNumber,
		MD5:    MD5,
		Size:   contentLength,
	}
	return &UploadPartOutput{
		ETag:                 hex.EncodeToString(MD5),
		ServerSideEncryption: upload.Object.ServerSideEncryption,
		SSEKMSKeyId:          upload.Object.SSEKMSKeyId,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html
func (s *S3) ListParts(input ListPartsInput) (*ListPartsOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	upload, ok := s.multipartUploads[input.UploadId]
	if !ok {
		return nil, awserrors.XXX_TODO("no upload")
	}

	maxParts := 1000
	if input.MaxParts != nil {
		maxParts = *input.MaxParts
	}

	var parts []Part
	for _, part := range upload.Parts {
		parts = append(parts, part)
	}
	slices.SortFunc(parts, func(a, b Part) bool {
		return a.Number < b.Number
	})

	startIndex := 0
	if input.PartNumberMarker != nil {
		startIndex = slices.IndexFunc(parts, func(p Part) bool {
			return p.Number == *input.PartNumberMarker
		})
	}

	output := &ListPartsOutput{
		Bucket:   input.Bucket,
		Key:      input.Key,
		UploadId: input.UploadId,
		MaxParts: maxParts,
	}

	i := startIndex
	for ; i < len(parts) && len(output.Part) < maxParts; i++ {
		output.Part = append(output.Part, ListPartsOutputPart{
			ETag:       hex.EncodeToString(parts[i].MD5),
			PartNumber: parts[i].Number,
			Size:       parts[i].Size,
		})
	}

	output.PartNumberMarker = i
	if i < len(parts) {
		output.IsTruncated = true
		output.NextPartNumberMarker = parts[i].Number
	}
	return output, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
func (s *S3) CompleteMultipartUpload(input CompleteMultipartUploadInput) (*CompleteMultipartUploadOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upload, ok := s.multipartUploads[input.UploadId]
	if !ok {
		return nil, awserrors.XXX_TODO("no upload")
	}

	if upload.Status != UploadStatusInProgress {
		return nil, awserrors.XXX_TODO("bad upload status")
	}

	if upload.Bucket != input.Bucket || upload.Key != input.Key {
		return nil, awserrors.XXX_TODO("wrong upload")
	}

	slices.SortFunc(input.Part, func(a, b APIPart) bool {
		return a.PartNumber < b.PartNumber
	})

	object := upload.Object

	var totalContentLength int64
	var combinedMD5s []byte
	for _, partSpec := range input.Part {
		part, ok := upload.Parts[partSpec.PartNumber]
		if !ok {
			return nil, awserrors.XXX_TODO("missing part")
		}

		if partSpec.ETag != hex.EncodeToString(part.MD5) {
			return nil, awserrors.XXX_TODO("wrong part")
		}

		combinedMD5s = append(combinedMD5s, part.MD5...)
		object.Parts = append(object.Parts, part)
		totalContentLength += part.Size
	}
	object.ContentLength = totalContentLength
	object.ETag = etag(combinedMD5s) + "-" + strconv.Itoa(len(input.Part))

	s.buckets[input.Bucket].objects[input.Key] = &object
	upload.Status = UploadStatusCompleted

	return &CompleteMultipartUploadOutput{
		Bucket:               input.Bucket,
		Key:                  input.Key,
		Location:             fmt.Sprintf("http://%s/%s/%s", s.addr, input.Bucket, input.Key),
		ETag:                 object.ETag,
		ServerSideEncryption: object.ServerSideEncryption,
		SSEKMSKeyId:          object.SSEKMSKeyId,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html
func (s *S3) AbortMultipartUpload(input AbortMultipartUploadInput) (*Response204, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upload, ok := s.multipartUploads[input.UploadId]
	if !ok {
		return nil, awserrors.XXX_TODO("no upload")
	}

	if upload.Status == UploadStatusCompleted {
		// TODO: check this behavior
		return nil, awserrors.XXX_TODO("bad upload status")
	}

	upload.Status = UploadStatusCompleted
	return response204, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
func (s *S3) GetBucketTagging(input GetBucketTaggingInput) (*GetBucketTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	return &GetBucketTaggingOutput{
		TagSet: b.TagSet,
	}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html
func (s *S3) PutBucketTagging(input PutBucketTaggingInput) (*PutBucketTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}
	b.TagSet = input.TagSet

	return &PutBucketTaggingOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
func (s *S3) DeleteBucketTagging(input DeleteBucketTaggingInput) (*Response204, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, awserrors.XXX_TODO("no bucket")
	}

	b.TagSet = TagSet{}
	return response204, nil
}
