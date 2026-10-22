package errors

import (
	"fmt"
)

// RequestError represents an error that occurred during an API request
type RequestError struct {
	Operation string `json:"operation"`
	error     error  `json:"-"`
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%s: unable to complete api request [err=%s]", e.Operation, e.error)
}

func NewRequestError(operation string, err error) error {
	return &RequestError{
		Operation: operation,
		error:     err,
	}
}
