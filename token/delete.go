package token

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/pkg/errors"
)

//Delete is used to delete a user auth token if a user auth token is passed
type Delete struct {
	VerifyAuthToken Verify
	TokenRepo       TokenRepo
}

//Execute runs nil if the "deleteToken" param was successfully deleted.
//Otherwise it returns a error. err.Authentication() if not authenticated.
//err.Authorization() if not authorized to delete token.
func (u Delete) Execute(deleteToken string, authToken string) error {
	userID, err := u.VerifyAuthToken.Execute(authToken)

	if err != nil {
		return err
	}

	t, err := u.TokenRepo.Get(deleteToken)
	if err != nil {
		return errors.Wrap(err, "retrieving delete token failed")
	}

	if (t == Token{}) {
		return errs.NewNotFoundError("token not found")
	}

	if t.UserID != userID {
		return errs.NewAuthorizationError("you are not authorized to delete this token")
	}

	err = errors.Wrap(u.TokenRepo.Delete(deleteToken), "error deleting token")

	return err
}
