package s3

import "aws-in-a-box/awserrors"

func NotFound() *awserrors.Error {
	return &awserrors.Error{
		Code: 404,
		Body: awserrors.ErrorBody{
			Type: "NotFound",
		},
	}
}

func NoSuchBucket(bucket string) *awserrors.Error {
	return &awserrors.Error{
		Code: 404,
		Body: awserrors.ErrorBody{
			Type:          "NoSuchBucket",
			Message:       "The specified bucket does not exist",
			LegacyMessage: "The specified bucket does not exist",
		},
	}
}

func VersionConflict(key string) *awserrors.Error {
	return &awserrors.Error{
		Code: 409,
		Body: awserrors.ErrorBody{
			Type:          "VersionConflict",
			Message:       "An object already exists with this key. Conditional PutObject failed",
			LegacyMessage: "An object already exists with this key. Conditional PutObject failed",
		},
	}
}
