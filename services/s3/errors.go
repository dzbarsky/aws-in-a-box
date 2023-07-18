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
