package awserrors

type Error struct {
	Code int
	Body any
}

type ErrorBody struct {
	Type    string `json:"__type"`
	Message string
}

func generate400Exception(typ, message string) *Error {
	return &Error{
		Code: 400,
		Body: ErrorBody{
			Type:    typ,
			Message: message,
		},
	}
}

func InvalidArgumentException(message string) *Error {
	return generate400Exception("InvalidArgumentException", message)
}

func LimitExceededException(message string) *Error {
	return generate400Exception("LimitExceededException", message)
}

func ResourceNotFoundException(message string) *Error {
	return generate400Exception("ResourceNotFoundException", message)
}

func ResourceInUseException(message string) *Error {
	return generate400Exception("ResourceInUseException", message)
}
