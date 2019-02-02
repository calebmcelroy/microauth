package auth

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

// newAuthorizationError creates an error with
// your msg that implements Authorization()
func newAuthorizationError(msg string) error {
	return authorizationError{customError{errors.New(msg)}}
}

// IsAuthorizationError checks if authorization error.
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

// errs.newAuthenticationError creates an error with
// your msg that implements Authentication()
func newAuthenticationError(msg string) error {
	return authenticationError{customError{errors.New(msg)}}
}

// IsAuthenticationError checks if authentication error.
// Behavior checking prevents coupling to an error type.
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

// newNotFoundError creates an error with
// your msg that implements NotFound()
func newNotFoundError(msg string) error {
	return notFoundError{customError{errors.New(msg)}}
}

// IsNotFoundError checks if whatever you requested could not be found.
// Behavior checking prevents coupling to an error type.
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

// newInvalidParamsError creates an error with
// your msg that implements InvalidParams()
func newInvalidParamsError(msg string) error {
	return invalidParamsError{customError{errors.New(msg)}}
}

// IsInvalidParamsError checks if error with the parameters used.
// Behavior checking prevents coupling to an error type.
func IsInvalidParamsError(err error) bool {
	type invalidParams interface {
		InvalidParams() bool
	}
	e, ok := err.(invalidParams)
	return ok && e.InvalidParams()
}
