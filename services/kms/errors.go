package kms

import "aws-in-a-box/awserrors"

func InvalidAliasNameException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("InvalidAliasNameException", message)
}

func AlreadyExistsException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("AlreadyExistsException", message)
}

func DisabledException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("DisabledException", message)
}

func InvalidCiphertextException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("InvalidCiphertextException", message)
}

func KMSInternalException(message string) *awserrors.Error {
	return &awserrors.Error{
		Code: 500,
		Body: awserrors.ErrorBody{
			Type:    "KMSInternalException",
			Message: message,
		},
	}
}

func NotFoundException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("NotFoundException", message)
}

func TagException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("TagException", message)
}

func UnsupportedOperationException(message string) *awserrors.Error {
	return awserrors.Generate400ExceptionWithLegacyMesageField("UnsupportedOperationException", message)
}

func InvalidParameterCombination(message string) *awserrors.Error {
	return awserrors.Generate400Exception("InvalidParameterCombination", message)
}

func ValidationException(message string) *awserrors.Error {
	return awserrors.Generate400Exception("ValidationException", message)
}

func XXXTodoException(message string) *awserrors.Error {
	return awserrors.XXX_TODO(message)
}
