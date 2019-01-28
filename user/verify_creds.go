package user

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/pkg/errors"
)

//VerifyCreds is used to validate a user's credentials
type VerifyCreds struct {
	UserRepo UserRepo
}

//Execute returns userID on success and empty userID if invalid.
func (u VerifyCreds) Execute(username string, password string) (userID string, err error) {
	if username == "" || password == "" {
		return "", errs.NewInvalidParamsError("Username and password are required")
	}

	id, e := u.UserRepo.Authenticate(username, password)

	if e != nil && !errs.IsAuthenticationError(e) {
		e = errors.Wrap(e, "error verifying user credentials")
	}

	return id, e
}
