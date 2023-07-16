package s3

import (
	"encoding/xml"
)

type CreateBucketInput struct {
	Bucket string
}

type CreateBucketOutput struct {
	Location string
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
	ServerSideEncryption    string `xml:"-"`
	SSEKMSKeyId             string `xml:"-"`
	SSEKMSEncryptionContext string `xml:"-"`
}

type UploadPartInput struct {
	Bucket     string
	Key        string
	UploadId   string
	PartNumber int
	Data       []byte
}

type UploadPartOutput struct {
	ETag                 string
	ServerSideEncryption string
	SSEKMSKeyId          string
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
	ServerSideEncryption string `xml:"-"`
	SSEKMSKeyId          string `xml:"-"`
}

type DeleteObjectInput struct {
	Bucket string `s3:"bucket"`
	Key    string `s3:"key"`
}

type DeleteObjectOutput struct{}
