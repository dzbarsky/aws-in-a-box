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
