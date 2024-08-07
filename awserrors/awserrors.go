package awserrors

type Error struct {
	Code int
	Body ErrorBody
}

type ErrorBody struct {
	Type          string `json:"__type"`
	Message       string `json:"Message,omitempty"`
	LegacyMessage string `json:"message,omitempty"`
}

func Generate400Exception(typ, message string) *Error {
	return &Error{
		Code: 400,
		Body: ErrorBody{
			Type:    typ,
			Message: message,
		},
	}
}

func Generate400ExceptionWithLegacyMesageField(typ, message string) *Error {
	return &Error{
		Code: 400,
		Body: ErrorBody{
			Type:          typ,
			LegacyMessage: message,
		},
	}
}

func InvalidArgumentException(message string) *Error {
	return Generate400Exception("InvalidArgumentException", message)
}

func LimitExceededException(message string) *Error {
	return Generate400Exception("LimitExceededException", message)
}

func ResourceNotFoundException(message string) *Error {
	return Generate400Exception("ResourceNotFoundException", message)
}

func ResourceInUseException(message string) *Error {
	return Generate400Exception("ResourceInUseException", message)
}

func ConditionalCheckFailedException(message string) *Error {
	return Generate400Exception("ConditionalCheckFailedException", message)
}

func XXX_TODO(message string) *Error {
	return &Error{
		Code: 500,
		Body: ErrorBody{
			Type:    "XXX_TODO",
			Message: message,
		},
	}
}
