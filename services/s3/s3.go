package s3

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/exp/maps"

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
	Objects       map[string]*Object
	CreatedAtUnix int64 // Not using time.Time so that it round-trips gob properly.
	TagSet        TagSet
}

type UploadStatus int

const (
	UploadStatusInProgress UploadStatus = iota
	UploadStatusCompleted
	UploadStatusAborted
)

type MultipartUpload struct {
	Status  UploadStatus
	Bucket  string
	Key     string
	Tagging string
	Parts   map[int]Part
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
	addr string

	// Persistence dirs.
	casDir      string
	metadataDir string

	mu               sync.Mutex
	buckets          map[string]*Bucket
	multipartUploads map[string]*MultipartUpload
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

	buckets := make(map[string]*Bucket)
	multipartUploads := make(map[string]*MultipartUpload)

	var metadataDir, casDir string
	if options.PersistDir == "" {
		var err error
		casDir, err = os.MkdirTemp("", "aws-in-a-box-s3")
		if err != nil {
			return nil, err
		}
	} else {
		metadataDir = filepath.Join(options.PersistDir, "s3")
		casDir = filepath.Join(metadataDir, "cas")
		err := os.MkdirAll(casDir, 0700)
		if err != nil {
			return nil, err
		}

		err = loadMetadata(metadataDir, buckets, multipartUploads)
		if err != nil {
			options.Logger.Warn(fmt.Sprintf(
				"Could not restore persisted data: %v", err))
		}
	}

	return &S3{
		logger:           options.Logger,
		addr:             options.Addr,
		metadataDir:      metadataDir,
		casDir:           casDir,
		buckets:          buckets,
		multipartUploads: multipartUploads,
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
		CreatedAtUnix: time.Now().Unix(),
		Objects:       make(map[string]*Object),
	}

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
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
		return nil, NoSuchBucket(input.Bucket)
	}

	return &HeadBucketOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
func (s *S3) ListBuckets(input ListBucketsInput) (*ListBucketsOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := &ListBucketsOutput{}
	for name, b := range s.buckets {
		resp.Buckets.Buckets = append(resp.Buckets.Buckets, ListBuckets_Bucket{
			Name:         name,
			CreationDate: time.Unix(b.CreatedAtUnix, 0).Format("2006-01-02T15:04:05+07:00"),
		})
	}

	return resp, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
func (s *S3) DeleteBucket(input DeleteBucketInput) (*Response204, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if ok {
		return nil, awserrors.XXX_TODO("bucket already exists")
	}

	if len(b.Objects) != 0 {
		return nil, awserrors.XXX_TODO("bucket must be empty")
	}

	delete(s.buckets, input.Bucket)

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

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

type ByteRange struct {
	// inclusive
	startByte int64
	// exclusive
	endByte int64
}

func parseRangeHeader(rangeHeader string, o *Object) ([]ByteRange, *awserrors.Error) {
	bytesPrefix := "bytes="
	if !strings.HasPrefix(rangeHeader, bytesPrefix) {
		awserrors.XXX_TODO("unknown range header unit")
	}

	ranges := strings.Split(rangeHeader[len(bytesPrefix):], ",")
	var result []ByteRange

	for _, encodedRange := range ranges {
		trimmed := strings.TrimSpace(encodedRange)
		splitRange := strings.Split(trimmed, "-")
		if len(splitRange) != 2 {
			return nil, awserrors.XXX_TODO("invalid range too many -")
		}

		// indexed from end of resource
		if splitRange[0] == "" {
			suffix, err := strconv.ParseInt(splitRange[1], 10, 64)
			if err != nil {
				return nil, awserrors.XXX_TODO(err.Error())
			}
			result = append(result, ByteRange{
				startByte: o.ContentLength - suffix,
				endByte:   o.ContentLength,
			})
			continue

		}

		// Suffix
		if splitRange[1] == "" {
			startByte, err := strconv.ParseInt(splitRange[0], 10, 64)
			if err != nil {
				return nil, awserrors.XXX_TODO(err.Error())
			}
			result = append(result, ByteRange{
				startByte: startByte,
				endByte:   o.ContentLength,
			})
			continue
		}

		// Both numbers included
		startByte, err := strconv.ParseInt(splitRange[0], 10, 64)
		if err != nil {
			return nil, awserrors.XXX_TODO(err.Error())
		}
		endByteInclusive, err := strconv.ParseInt(splitRange[1], 10, 64)
		if err != nil {
			return nil, awserrors.XXX_TODO(err.Error())
		}
		result = append(result, ByteRange{
			startByte: startByte,
			endByte:   endByteInclusive + 1,
		})
	}
	return result, nil
}

// Returns a reader, a content length, and an error.
//
// When given a range that stretches beyond the length of an object, S3 will return the piece of
// the object that exists, with an appropriate content length.
//
// When given a range that is entirely not within the object, S3 will return a 416 error. This is
// currently not implemented.
func (s *S3) readerForRange(object *Object, br ByteRange) (io.Reader, int64, *awserrors.Error) {
	var parts []Part
	if len(object.Parts) == 0 {
		parts = []Part{{MD5: object.MD5, Size: object.ContentLength}}
	} else {
		parts = object.Parts
	}

	// bytesUntilStart is zero if we have already passed the start, otherwise it is the total number
	// of bytes we must skip before starting our response.
	bytesUntilStart := br.startByte
	bytesUntilEnd := br.endByte
	var readers []io.Reader
	readLength := int64(0)
	// Loop over parts in order, updating bytesUntilStart and bytesUntilEnd. If the chunk lies
	// within the range that must be returned, use a section reader to capture the appropriate range.
	for _, part := range parts {
		// If we've already passed the end, break
		if bytesUntilEnd <= 0 {
			break
		}

		size := part.Size
		// If we haven't reached the start yet, skip the chunk.
		if bytesUntilStart > size {
			bytesUntilStart -= size
			bytesUntilEnd -= size
			continue
		}

		// Otherwise, open a reader for this chunk.
		f, err := os.Open(s.filepath(part.MD5))
		if err != nil {
			return nil, 0, awserrors.XXX_TODO(err.Error())
		}
		var bytesToReadFromThisChunk int64
		if bytesUntilEnd >= size {
			// Read the entire chunk after the start.
			bytesToReadFromThisChunk = size - bytesUntilStart
		} else {
			// Read everything from the start until the end.
			bytesToReadFromThisChunk = bytesUntilEnd - bytesUntilStart
		}

		readers = append(readers, io.NewSectionReader(f, bytesUntilStart, bytesToReadFromThisChunk))
		bytesUntilEnd -= (bytesUntilStart + bytesToReadFromThisChunk)
		bytesUntilStart = 0
		readLength += bytesToReadFromThisChunk
	}
	if bytesUntilStart > 0 {
		// For whatever reason, the AWS sdk requires that this error message is formatted correctly.
		errorObj := InvalidRangeError{
			Code:             "InvalidRange",
			Message:          "The requested range is not satisfiable",
			RangeRequested:   fmt.Sprintf("bytes=%d-%d", br.startByte, br.endByte-1),
			ActualObjectSize: object.ContentLength,
		}
		serializedError, err := xml.Marshal(errorObj)
		if err != nil {
			return nil, 0, awserrors.XXX_TODO(err.Error())
		}

		return nil, 0, &awserrors.Error{
			Code: 416,
			Body: awserrors.ErrorBody{
				Type:    "InvalidRange",
				Message: string(serializedError),
			},
		}
	}
	return io.MultiReader(readers...), readLength, nil
}

func (s *S3) getObject(input GetObjectInput, includeBody bool) (*GetObjectOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	object, ok := b.Objects[input.Key]
	if !ok {
		return nil, NotFound()
	}

	timeFormat := "Mon, 02 Jan 2006 15:04:05 GMT"
	output := &GetObjectOutput{
		ContentLength:        object.ContentLength,
		ETag:                 object.ETag,
		ContentType:          object.ContentType,
		ServerSideEncryption: object.ServerSideEncryption,
		SSECustomerAlgorithm: object.SSECustomerAlgorithm,
		SSECustomerKey:       object.SSECustomerKey,
		SSEKMSKeyId:          object.SSEKMSKeyId,
		// Bafflingly, This format is expected here.
		LastModified: time.Now().UTC().Format(timeFormat),
		HttpStatus:   http.StatusOK,
	}
	if includeBody {
		var ranges []ByteRange
		if input.Range != "" {
			var err *awserrors.Error
			ranges, err = parseRangeHeader(input.Range, object)
			if err != nil {
				return nil, err
			}
		} else {
			ranges = []ByteRange{
				{
					startByte: 0,
					endByte:   object.ContentLength,
				},
			}
		}

		var readers []io.Reader
		totalLength := int64(0)
		for _, rangeItem := range ranges {
			readerForRange, readLength, err := s.readerForRange(object, rangeItem)
			totalLength += readLength
			if err != nil {
				return nil, err
			}
			readers = append(readers, readerForRange)
		}
		output.Body = io.MultiReader(readers...)
		output.ContentLength = totalLength
		// S3 always sends StatusPartialContent if a range header was specified in the original request.
		if input.Range != "" {
			output.HttpStatus = http.StatusPartialContent
			if len(ranges) == 1 {
				// Content-Range is inclusive on the end, where ranges[0].endByte is exclusive. We subtract one to convert.
				output.ContentRange = fmt.Sprintf("bytes %d-%d/%d", ranges[0].startByte, ranges[0].endByte-1, object.ContentLength)
			} else {
				// If there is more than one range specified, just use * to indicate unknown.
				output.ContentRange = fmt.Sprintf("bytes */%d", object.ContentLength)
			}
		}
	}
	return output, nil
}

func (s *S3) filepath(MD5 []byte) string {
	return filepath.Join(s.casDir, hex.EncodeToString(MD5))
}

// drainReaderToMD5Store returns the MD5 and the number of bytes written
func (s *S3) drainReaderToMD5Store(r io.Reader) ([]byte, int64, error) {
	md5Writer := md5.New()
	tempPath := filepath.Join(s.casDir, uuid.Must(uuid.NewV4()).String())
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
		return nil, NoSuchBucket(input.Bucket)
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

	if input.IfNoneMatch == "*" && b.Objects[input.Key] != nil {
		return nil, VersionConflict(input.Key)
	}
	b.Objects[input.Key] = object

	err = s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

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

	// "bucket/path/to/key"
	copySource, err := url.PathUnescape(input.CopySource)
	if err != nil {
		return nil, awserrors.XXX_TODO(err.Error())
	}
	parts := strings.SplitN(copySource, "/", 2)
	sourceBucket := parts[0]
	sourceKey := parts[1]

	b, ok := s.buckets[sourceBucket]
	if !ok {
		return nil, NoSuchBucket(sourceBucket)
	}

	object, ok := b.Objects[sourceKey]
	if !ok {
		return nil, awserrors.XXX_TODO("no source item: " + sourceKey)
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
		return nil, NoSuchBucket(input.Bucket)
	}

	destBucket.Objects[input.Key] = object

	err = s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

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
		return nil, NoSuchBucket(input.Bucket)
	}

	delete(b.Objects, input.Key)

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return &DeleteObjectOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html
func (s *S3) DeleteObjects(input DeleteObjectsInput) (*DeleteObjectsOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, bucketExists := s.buckets[input.Bucket]

	output := &DeleteObjectsOutput{}
	for _, object := range input.Object {
		if !bucketExists {
			err := NoSuchBucket(input.Bucket).Body
			output.Error = append(output.Error, DeleteObjectsError{
				Code:    err.Type,
				Key:     object.Key,
				Message: err.Message,
			})
			continue
		}

		delete(b.Objects, object.Key)
		if !input.Quiet {
			output.Deleted = append(output.Deleted, DeleteObjectsDeleted{
				Key: object.Key,
			})
		}
	}

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return output, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html
func (s *S3) GetObjectTagging(input GetObjectTaggingInput) (*GetObjectTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	object, ok := b.Objects[input.Key]
	if !ok {
		return nil, NotFound()
	}

	tagging := &GetObjectTaggingOutput{}
	if len(object.Tagging) > 0 {
		for _, kv := range strings.Split(object.Tagging, "&") {
			kvs := strings.Split(kv, "=")
			if len(kvs) != 2 {
				return nil, awserrors.XXX_TODO(fmt.Sprintf("invalid tagging: '%s', '%s'", kv, object.Tagging))
			}
			tagging.TagSet.Tag = append(tagging.TagSet.Tag, APITag{
				Key:   kvs[0],
				Value: kvs[1],
			})
		}
	}

	return tagging, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html
func (s *S3) PutObjectTagging(input PutObjectTaggingInput) (*PutObjectTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	object, ok := b.Objects[input.Key]
	if !ok {
		return nil, NotFound()
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

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return &PutObjectTaggingOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html
func (s *S3) DeleteObjectTagging(input DeleteObjectTaggingInput) (*Response204, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	object, ok := b.Objects[input.Key]
	if !ok {
		return nil, NotFound()
	}
	object.Tagging = ""

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return response204, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html
func (s *S3) CreateMultipartUpload(input CreateMultipartUploadInput) (*CreateMultipartUploadOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	uploadId := base64.RawURLEncoding.EncodeToString(uuid.Must(uuid.NewV4()).Bytes())
	s.multipartUploads[uploadId] = &MultipartUpload{
		Status:  UploadStatusInProgress,
		Bucket:  input.Bucket,
		Key:     input.Key,
		Tagging: input.Tagging,
		Parts:   make(map[int]Part),
		// Just for metadata
		Object: Object{
			ContentType:             input.ContentType,
			ServerSideEncryption:    input.ServerSideEncryption,
			SSEKMSKeyId:             input.SSEKMSKeyId,
			SSEKMSEncryptionContext: input.SSEKMSEncryptionContext,
		},
	}

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
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

	err = s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
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
		return nil, NoSuchBucket(input.Bucket)
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
	slices.SortFunc(parts, func(a, b Part) int {
		return a.Number - b.Number
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

	if input.IfNoneMatch == "*" && s.buckets[input.Bucket].Objects[input.Key] != nil {
		return nil, VersionConflict(input.Key)
	}

	slices.SortFunc(input.Part, func(a, b APIPart) int {
		return a.PartNumber - b.PartNumber
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
	object.Tagging = upload.Tagging

	s.buckets[input.Bucket].Objects[input.Key] = &object
	upload.Status = UploadStatusCompleted

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

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

	if upload.Bucket != input.Bucket || upload.Key != input.Key {
		// TODO: check this behavior
		return nil, awserrors.XXX_TODO("bad upload")
	}

	upload.Status = UploadStatusCompleted

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return response204, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
func (s *S3) GetBucketTagging(input GetBucketTaggingInput) (*GetBucketTaggingOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
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
		return nil, NoSuchBucket(input.Bucket)
	}
	b.TagSet = input.TagSet

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return &PutBucketTaggingOutput{}, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
func (s *S3) DeleteBucketTagging(input DeleteBucketTaggingInput) (*Response204, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	b.TagSet = TagSet{}

	err := s.persistMetadata()
	if err != nil {
		return nil, awserrors.XXX_TODO(fmt.Sprintf("failed to persist: %v", err))
	}

	return response204, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
func (s *S3) ListObjectsV2(input ListObjectsV2Input) (*ListObjectsV2Output, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[input.Bucket]
	if !ok {
		return nil, NoSuchBucket(input.Bucket)
	}

	// Gather a list of all keys in bucket, sort them.
	var keysSorted []string
	for key := range b.Objects {
		if input.Prefix != nil && !strings.HasPrefix(key, *input.Prefix) {
			continue
		}
		keysSorted = append(keysSorted, key)
	}
	sort.Strings(keysSorted)

	maxKeys := 1000
	if input.MaxKeys != nil {
		maxKeys = *input.MaxKeys
	}

	// Gather up to maxKeys to include
	isTruncated := false
	continuationToken := ""
	var keysToInclude []string
	for _, key := range keysSorted {
		if input.Delimiter != nil && strings.Contains(key, *input.Delimiter) {
			continue
		}

		if len(keysToInclude) >= maxKeys {
			isTruncated = true
			continuationToken = key
			break
		}

		if input.StartAfter != nil && key < *input.StartAfter {
			continue
		}

		if input.ContinuationToken != nil && key < *input.ContinuationToken {
			continue
		}
		keysToInclude = append(keysToInclude, key)
	}

	var contents []ListObjectsV2Object
	for _, keyToInclude := range keysToInclude {
		object := b.Objects[keyToInclude]
		contents = append(contents, ListObjectsV2Object{
			ETag: object.ETag,
			Key:  keyToInclude,
			Size: int(object.ContentLength),
			// TODO: Complete guess on format
			LastModified: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}

	response := &ListObjectsV2Output{
		Name:                  input.Bucket,
		IsTruncated:           isTruncated,
		Contents:              contents,
		ContinuationToken:     input.ContinuationToken,
		KeyCount:              len(contents),
		MaxKeys:               maxKeys,
		NextContinuationToken: continuationToken,
		Prefix:                input.Prefix,
		StartAfter:            input.StartAfter,
		// TODO(zbarsky): Do we just echo this? Docs seem unclear.
		Delimiter: input.Delimiter,
	}

	if input.Delimiter != nil {
		commonPrefixes := make(map[string]struct{})
		for _, key := range keysSorted {
			i := strings.Index(key, *input.Delimiter)
			if i != -1 {
				commonPrefixes[key[:i+len(*input.Delimiter)]] = struct{}{}
			}
		}

		prefixesSorted := maps.Keys(commonPrefixes)
		sort.Strings(prefixesSorted)
		for _, p := range prefixesSorted {
			response.CommonPrefixes = append(response.CommonPrefixes, Prefix{p})
		}
	}

	// TODO(zbarsky): Method may be incomplete, here's what AWS docs say:
	// When you query ListObjectsV2 with a delimiter during in-progress multipart uploads,
	// the CommonPrefixes response parameter contains the prefixes that are associated with
	// the in-progress multipart uploads.

	return response, nil
}
