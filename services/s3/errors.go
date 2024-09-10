package s3

import "aws-in-a-box/awserrors"

// See https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html
func err(code int, errorType string, message string) *awserrors.Error {
	return &awserrors.Error{
		Code: code,
		Body: awserrors.ErrorBody{
			Type:          errorType,
			Message:       message,
			LegacyMessage: message,
		},
	}
}

func NotFound() *awserrors.Error {
	return &awserrors.Error{
		Code: 404,
		Body: awserrors.ErrorBody{
			Type: "NotFound",
		},
	}
}

func InvalidPart() *awserrors.Error {
	return err(400, "InvalidPart", "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag.")
}

func NoSuchBucket(bucket string) *awserrors.Error {
	return err(404, "NoSuchBucket", "The specified bucket does not exist.")
}

func NoSuchUpload() *awserrors.Error {
	return err(404, "NoSuchUpload", "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed.")
}

func BucketNotEmpty(bucket string) *awserrors.Error {
	return err(409, "BucketNotEmpty", "The bucket you tried to delete is not empty.")
}

func BucketAlreadyExists() *awserrors.Error {
	return err(409, "BucketAlreadyExists", "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.")
}

func PreconditionFailed() *awserrors.Error {
	return err(412, "PreconditionFailed", "At least one of the preconditions you specified did not hold.")
}
