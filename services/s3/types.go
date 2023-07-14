package s3

import "encoding/xml"

type CreateBucketInput struct {
	Bucket string
}

type CreateBucketOutput struct {
	Location string
}

type GetObjectTaggingOutput struct {
	Tagging Tagging
}

type Tagging struct {
	TagSet struct {
		Tag []APITag
	}
}

type APITag struct {
	Key   string
	Value string
}

type PutObjectTaggingInput struct {
	Bucket  string
	Key     string
	Tagging Tagging
}

type PutObjectTaggingOutput struct{}

type CopyObjectOutput struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string
	LastModified string
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
	UploadId string
	Bucket   string
	Key      string
	Part     []APIPart
}

type APIPart struct {
	XMLName    xml.Name `xml:"Part"`
	ETag       string
	PartNumber int
}

type CompleteMultipartUploadOutput struct {
	XMLName                 xml.Name `xml:"CompleteMultipartUploadResult"`
	Location                string
	Bucket                  string
	Key                     string
	ETag                    string
	ServerSideEncryption    string `xml:"-"`
	SSEKMSKeyId             string `xml:"-"`
	SSEKMSEncryptionContext string `xml:"-"`
}
