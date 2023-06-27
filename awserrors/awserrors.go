package awserrors

type Error struct {
	Code int
	Body any
}

type ErrorBody struct {
	Type string `json:"__type"`
	Message string
}

func InvalidArgumentException(message string) *Error {
	return &Error {
		Code: 400,
		Body: ErrorBody{
			Type: "InvalidArgumentException",
			Message: message,
		},
	}
}

func ResourceNotFoundException(message string) *Error {
	return &Error {
		Code: 400,
		Body: ErrorBody{
			Type: "ResourceNotFoundException",
			Message: message,
		},
	}
}
