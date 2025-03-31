package status

import (
	"fmt"
)

type Error struct {
	cause  error
	Status Status
}

func NewError(err error, status Status) Error {
	return Error{cause: err, Status: status}
}

func (e Error) Error() string {
	cause := ""
	if e.cause != nil {
		cause = e.cause.Error()
	}

	return fmt.Sprintf(
		"%d %s: %q", e.Status.Code, e.Status.ReasonPhrase, cause,
	)
}

func (e Error) Cause() error {
	return e.cause
}
