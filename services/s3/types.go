package s3

import (
	"encoding/xml"
	"io"
)

type Response204 struct{}

var response204 = &Response204{}

type CreateBucketInput struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	Bucket             string   `s3:"bucket"`
	LocationConstraint string
}

type CreateBucketOutput struct {
	Location string
}

type DeleteBucketInput struct {
	Bucket string `s3:"bucket"`
}

type HeadBucketInput struct {
	Bucket string `s3:"bucket"`
}

type HeadBucketOutput struct{}

type GetBucketTaggingInput struct {
	Bucket string `s3:"bucket"`
}

type GetBucketTaggingOutput struct {
	XMLName xml.Name `xml:"Tagging"`
	TagSet  TagSet
}

type PutBucketTaggingInput struct {
	XMLName xml.Name `xml:"Tagging"`
	Bucket  string   `s3:"bucket"`
	TagSet  TagSet
}

type PutBucketTaggingOutput struct{}

type DeleteBucketTaggingInput struct {
	Bucket string `s3:"bucket"`
}

type GetObjectTaggingInput struct {
	Bucket string `s3:"bucket"`
	Key    string `s3:"key"`
}

type GetObjectTaggingOutput struct {
	XMLName xml.Name `xml:"Tagging"`
	TagSet  TagSet
}

type TagSet struct {
	Tag []APITag
}

type APITag struct {
	Key   string
	Value string
}

type PutObjectTaggingInput struct {
	XMLName xml.Name `xml:"Tagging"`
	Bucket  string   `s3:"bucket"`
	Key     string   `s3:"key"`
	TagSet  TagSet
}

type PutObjectTaggingOutput struct{}

type DeleteObjectTaggingInput struct {
	Bucket string `s3:"bucket"`
	Key    string `s3:"key"`
}

type GetObjectInput struct {
	Bucket               string `s3:"bucket"`
	Key                  string `s3:"key"`
	PartNumber           string `s3:"query:partNumber"`
	SSECustomerAlgorithm string `s3:"header:x-amz-server-side-encryption-customer-algorithm"`
	SSECustomerKey       string `s3:"header:x-amz-server-side-encryption-customer-key"`
	// TODO: md5 check
}

type GetObjectOutput struct {
	ContentLength        int64  `s3:"header:content-length"`
	ETag                 string `s3:"header:etag"`
	ContentType          string `s3:"header:content-type"`
	ServerSideEncryption string `s3:"header:x-amz-server-side-encryption"`
	SSECustomerAlgorithm string `s3:"header:x-amz-server-side-encryption-customer-algorithm"`
	SSECustomerKey       string `s3:"header:x-amz-server-side-encryption-customer-key"`
	// TODO: md5
	SSEKMSKeyId string `s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
	//PartsCount    int    `s3:"header:x-amz-mp-parts-count"`
	Body io.Reader `s3:"body"`
}

type PutObjectInput struct {
	Bucket                  string    `s3:"bucket"`
	Key                     string    `s3:"key"`
	Data                    io.Reader `s3:"body"`
	CopySource              string    `s3:"header:x-amz-copy-source"`
	MetadataDirective       string    `s3:"header:x-amz-metadata-directive"`
	ContentType             string    `s3:"header:content-type"`
	ServerSideEncryption    string    `s3:"header:x-amz-server-side-encryption"`
	SSEKMSKeyId             string    `s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
	SSEKMSEncryptionContext string    `s3:"header:x-amz-server-side-encryption-context"`
	SSECustomerAlgorithm    string    `s3:"header:x-amz-server-side-encryption-customer-algorithm"`
	// TODO: md5 check
	SSECustomerKey   string `s3:"header:x-amz-server-side-encryption-customer-key"`
	Tagging          string `s3:"header:x-amz-tagging"`
	TaggingDirective string `s3:"header:x-amz-tagging-directive"`
}

type PutObjectOutput struct {
	ETag                    string `s3:"header:etag"`
	SSECustomerAlgorithm    string `s3:"header:x-amz-server-side-encryption-customer-algorithm"`
	SSEKMSKeyId             string `s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
	SSEKMSEncryptionContext string `s3:"header:x-amz-server-side-encryption-context"`
}

type CopyObjectInput struct {
	Bucket                  string `s3:"bucket"`
	Key                     string `s3:"key"`
	CopySource              string `s3:"header:x-amz-copy-source"`
	MetadataDirective       string `s3:"header:x-amz-metadata-directive"`
	ContentType             string `s3:"header:content-type"`
	ServerSideEncryption    string `s3:"header:x-amz-server-side-encryption"`
	SSEKMSKeyId             string `s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
	SSEKMSEncryptionContext string `s3:"header:x-amz-server-side-encryption-context"`
	SSECustomerAlgorithm    string `s3:"header:x-amz-server-side-encryption-customer-algorithm"`
	SSECustomerKey          string `s3:"header:x-amz-server-side-encryption-customer-key"`
	Tagging                 string `s3:"header:x-amz-tagging"`
	TaggingDirective        string `s3:"header:x-amz-tagging-directive"`
}

type CopyObjectOutput struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string
	LastModified string
}

type CreateMultipartUploadInput struct {
	Bucket                  string `s3:"bucket"`
	Key                     string `s3:"key"`
	ContentType             string `s3:"header:content-type"`
	ServerSideEncryption    string `s3:"header:x-amz-server-side-encryption"`
	SSEKMSKeyId             string `s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
	SSEKMSEncryptionContext string `s3:"header:x-amz-server-side-encryption-context"`
}

type CreateMultipartUploadOutput struct {
	XMLName                 xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket                  string
	Key                     string
	UploadId                string
	ServerSideEncryption    string `xml:"-" s3:"header:x-amz-server-side-encryption"`
	SSEKMSKeyId             string `xml:"-" s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
	SSEKMSEncryptionContext string `xml:"-" s3:"header:x-amz-server-side-encryption-context"`
}

type UploadPartInput struct {
	Bucket     string    `s3:"bucket"`
	Key        string    `s3:"key"`
	UploadId   string    `s3:"query:uploadId"`
	PartNumber int       `s3:"query:partNumber"`
	Data       io.Reader `s3:"body"`
}

type UploadPartOutput struct {
	ETag                 string `s3:"header:etag"`
	ServerSideEncryption string `s3:"header:x-amz-server-side-encryption"`
	SSEKMSKeyId          string `s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
}

type ListPartsInput struct {
	Bucket               string `s3:"bucket"`
	Key                  string `s3:"key"`
	UploadId             string `s3:"query:uploadId"`
	PartNumberMarker     *int   `s3:"query:part-number-marker"`
	MaxParts             *int   `s3:"query:max-parts"`
	SSECustomerAlgorithm string `s3:"header:x-amz-server-side-encryption-customer-algorithm"`
	SSECustomerKey       string `s3:"header:x-amz-server-side-encryption-customer-key"`
	// TODO: md5 check
}

type ListPartsOutput struct {
	XMLName              xml.Name `xml:"ListPartsResult"`
	Bucket               string
	Key                  string
	UploadId             string
	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int
	IsTruncated          bool
	Part                 []ListPartsOutputPart
}

type ListPartsOutputPart struct {
	ETag string
	//LastModified
	PartNumber int
	Size       int64
}

type AbortMultipartUploadInput struct {
	UploadId string `s3:"query:uploadId"`
	Bucket   string `s3:"bucket"`
	Key      string `s3:"key"`
}

type CompleteMultipartUploadInput struct {
	XMLName  xml.Name `xml:"CompleteMultipartUpload"`
	UploadId string   `s3:"query:uploadId"`
	Bucket   string   `s3:"bucket"`
	Key      string   `s3:"key"`
	Part     []APIPart
}

type APIPart struct {
	XMLName    xml.Name `xml:"Part"`
	ETag       string
	PartNumber int
}

type CompleteMultipartUploadOutput struct {
	XMLName              xml.Name `xml:"CompleteMultipartUploadResult"`
	Location             string
	Bucket               string
	Key                  string
	ETag                 string
	ServerSideEncryption string `xml:"-" s3:"header:x-amz-server-side-encryption"`
	SSEKMSKeyId          string `xml:"-" s3:"header:x-amz-server-side-encryption-aws-kms-key-id"`
}

type DeleteObjectInput struct {
	Bucket string `s3:"bucket"`
	Key    string `s3:"key"`
}

type DeleteObjectOutput struct{}

type DeleteObjectsInput struct {
	XMLName xml.Name `xml:"Delete"`
	Bucket  string   `s3:"bucket"`
	Object  []struct {
		Key       string
		VersionId string
	}
	Quiet bool
}

type DeleteObjectsOutput struct {
	XMLName xml.Name `xml:"DeleteResult"`
	Deleted []DeleteObjectsDeleted
	Error   []DeleteObjectsError
}

type DeleteObjectsDeleted struct {
	//DeleteMarker          bool
	//DeleteMarkerVersionId string
	Key string
	//VersionId             string
}

type DeleteObjectsError struct {
	Code    string
	Key     string
	Message string
	//VersionId string
}
