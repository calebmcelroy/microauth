package usecase

import (
	"github.com/calebmcelroy/tradelead-auth/core/boundary"
	"github.com/pkg/errors"
)

//VerifyUserCreds is used to validate a user's credentials
type VerifyUserCreds struct {
	UserRepo boundary.UserRepo
}

//Execute returns userID on success and empty userID if invalid.
func (u VerifyUserCreds) Execute(username string, password string) (userID string, err error) {
	if username == "" || password == "" {
		return "", NewInvalidParamsError("Username and password are required")
	}

	id, e := u.UserRepo.Authenticate(username, password)

	if e != nil && !IsAuthenticationError(e) {
		e = errors.Wrap(e, "error verifying user credentials")
	}

	return id, e
}
