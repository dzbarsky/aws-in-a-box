package kms

import "aws-in-a-box/awserrors"

func InvalidAliasNameException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "InvalidAliasNameException",
			Message: message,
		},
	}
}

func AlreadyExistsException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "AlreadyExistsException",
			Message: message,
		},
	}
}

func DisabledException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "DisabledException",
			Message: message,
		},
	}
}


func KMSInternalException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 500,
		Body: awserrors.ErrorBody{
			Type: "KMSInternalException",
			Message: message,
		},
	}
}


func NotFoundException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "NotFoundException",
			Message: message,
		},
	}
}

func TagException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "TagException",
			Message: message,
		},
	}
}

func UnsupportedOperationException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "UnsupportedOperationException",
			Message: message,
		},
	}
}

func InvalidParameterCombination(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "InvalidParameterCombination",
			Message: message,
		},
	}
}

func XXXTodoException(message string) *awserrors.Error {
	return &awserrors.Error {
		Code: 400,
		Body: awserrors.ErrorBody{
			Type: "XXXTodoException",
			Message: message,
		},
	}
}