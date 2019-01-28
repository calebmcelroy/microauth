package token

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/calebmcelroy/tradelead-auth/user"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"time"
)

//Create usecase is used to create a token for a user
type Create struct {
	VerifyUserCreds user.VerifyCreds
	TokenRepo       TokenRepo
}

//Execute is used to run the usecase
func (u Create) Execute(username string, password string, remember bool) (token Token, err error) {
	if username == "" || password == "" {
		return Token{}, errs.NewInvalidParamsError("Username and password are required")
	}

	userID, credsErr := u.VerifyUserCreds.Execute(username, password)

	if credsErr != nil {
		return Token{}, credsErr
	}

	token = Token{}
	token.Token = uuid.New().String()
	token.UserID = userID

	if remember {
		token.Expiration = time.Now().Add(time.Hour * 24 * 30)
	} else {
		token.Expiration = time.Now().Add(time.Hour * 24)
	}

	repoErr := u.TokenRepo.Insert(token)

	if repoErr != nil {
		return Token{}, errors.Wrap(repoErr, "insert token failed")
	}

	return token, nil
}
