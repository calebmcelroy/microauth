package usecase

import (
	"github.com/pkg/errors"
	"time"

	"github.com/calebmcelroy/tradelead-auth/core/boundary"
	"github.com/calebmcelroy/tradelead-auth/core/entity"
	"github.com/google/uuid"
)

//CreateAuthToken usecase is used to create a token for a user
type CreateAuthToken struct {
	VerifyUserCreds VerifyUserCreds
	TokenRepo       boundary.TokenRepo
}

//Execute is used to run the usecase
func (u CreateAuthToken) Execute(username string, password string, remember bool) (token entity.Token, err error) {
	if username == "" || password == "" {
		return entity.Token{}, NewInvalidParamsError("Username and password are required")
	}

	userID, credsErr := u.VerifyUserCreds.Execute(username, password)

	if credsErr != nil {
		return entity.Token{}, credsErr
	}

	token = entity.Token{}
	token.Token = uuid.New().String()
	token.UserID = userID

	if remember {
		token.Expiration = time.Now().Add(time.Hour * 24 * 30)
	} else {
		token.Expiration = time.Now().Add(time.Hour * 24)
	}

	repoErr := u.TokenRepo.Insert(token)

	if repoErr != nil {
		return entity.Token{}, errors.Wrap(repoErr, "insert token failed")
	}

	return token, nil
}
