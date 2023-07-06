package kinesis

import "aws-in-a-box/awserrors"

func XXXTodoException(message string) *awserrors.Error {
	return &awserrors.Error{
		Code: 400,
		Body: awserrors.ErrorBody{
			Type:    "XXXTodoException",
			Message: message,
		},
	}
}
