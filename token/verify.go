package token

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/pkg/errors"
	"time"
)

//Verify is used to verify whether a token is valid or not and get the current user
type Verify struct {
	TokenRepo TokenRepo
}

//Execute returns userID if success or 0 if invalid.
func (u Verify) Execute(token string) (userID string, err error) {
	t, e := u.TokenRepo.Get(token)

	if e != nil {
		return "", errors.Wrap(e, "failed getting token")
	}

	tokenExpired := t.Expiration.Unix() > 0 && t.Expiration.Unix() < time.Now().Unix()
	tokenMatches := t.Token == token
	tokenUserEmpty := t.UserID == ""

	if tokenExpired || !tokenMatches || tokenUserEmpty {
		return "", errs.NewAuthenticationError("invalid token")
	}

	return t.UserID, nil
}
