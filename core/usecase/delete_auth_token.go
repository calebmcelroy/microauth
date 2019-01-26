package usecase

import (
	"github.com/calebmcelroy/tradelead-auth/core/boundary"
	"github.com/calebmcelroy/tradelead-auth/core/entity"
	"github.com/pkg/errors"
)

//DeleteAuthToken is used to delete a user auth token if a user auth token is passed
type DeleteAuthToken struct {
	VerifyAuthToken VerifyAuthToken
	TokenRepo       boundary.TokenRepo
}

//Execute runs nil if the "deleteToken" param was successfully deleted.
//Otherwise it returns a error. err.Authentication() if not authenticated.
//err.Authorization() if not authorized to delete token.
func (u DeleteAuthToken) Execute(deleteToken string, authToken string) error {
	userID, err := u.VerifyAuthToken.Execute(authToken)

	if err != nil {
		return err
	}

	t, err := u.TokenRepo.Get(deleteToken)
	if err != nil {
		return errors.Wrap(err, "retrieving delete token failed")
	}

	if (t == entity.Token{}) {
		return NewNotFoundError("token not found")
	}

	if t.UserID != userID {
		return NewAuthorizationError("you are not authorized to delete this token")
	}

	err = errors.Wrap(u.TokenRepo.Delete(deleteToken), "error deleting token")

	return err
}
