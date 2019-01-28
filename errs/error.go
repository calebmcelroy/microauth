package errs

import "errors"

type customError struct {
	err error
}

func (e customError) Error() string {
	return e.err.Error()
}

type authorizationError struct {
	customError
}

func (e authorizationError) Authorization() bool {
	return true
}

// NewAuthorizationError creates an error with
// your msg that implements Authorization()
func NewAuthorizationError(msg string) error {
	return authorizationError{customError{errors.New(msg)}}
}

// IsAuthorizationError checks if an error is an authorization error.
// It uses behavior checking therefore is not coupled to a type
func IsAuthorizationError(err error) bool {
	type authorization interface {
		Authorization() bool
	}
	e, ok := err.(authorization)
	return ok && e.Authorization()
}

type authenticationError struct {
	customError
}

func (e authenticationError) Authentication() bool {
	return true
}

// errs.NewAuthenticationError creates an error with
// your msg that implements Authentication()
func NewAuthenticationError(msg string) error {
	return authenticationError{customError{errors.New(msg)}}
}

// IsAuthenticationError checks if an error is an authentication error.
// It uses behavior checking therefore is not coupled to a type
func IsAuthenticationError(err error) bool {
	type authentication interface {
		Authentication() bool
	}
	e, ok := err.(authentication)
	return ok && e.Authentication()
}

type notFoundError struct {
	customError
}

func (e notFoundError) NotFound() bool {
	return true
}

// NewNotFoundError creates an error with
// your msg that implements NotFound()
func NewNotFoundError(msg string) error {
	return notFoundError{customError{errors.New(msg)}}
}

// IsNotFoundError checks if an error is a not found error.
// It uses behavior checking therefore is not coupled to a type
func IsNotFoundError(err error) bool {
	type notFound interface {
		NotFound() bool
	}
	e, ok := err.(notFound)
	return ok && e.NotFound()
}

type invalidParamsError struct {
	customError
}

func (e invalidParamsError) InvalidParams() bool {
	return true
}

// NewInvalidParamsError creates an error with
// your msg that implements InvalidParams()
func NewInvalidParamsError(msg string) error {
	return invalidParamsError{customError{errors.New(msg)}}
}

// IsInvalidParamsError checks if an error is an error in the params passed to a use case.
// It uses behavior checking therefore is not coupled to a type
func IsInvalidParamsError(err error) bool {
	type invalidParams interface {
		InvalidParams() bool
	}
	e, ok := err.(invalidParams)
	return ok && e.InvalidParams()
}
