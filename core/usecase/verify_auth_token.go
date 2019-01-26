package usecase

import (
	"github.com/pkg/errors"
	"time"

	"github.com/calebmcelroy/tradelead-auth/core/boundary"
)

//VerifyAuthToken is used to verify whether a token is valid or not and get the current user
type VerifyAuthToken struct {
	TokenRepo boundary.TokenRepo
}

//Execute returns userID if success or 0 if invalid.
func (u VerifyAuthToken) Execute(token string) (userID string, err error) {
	t, e := u.TokenRepo.Get(token)

	if e != nil {
		return "", errors.Wrap(e, "failed getting token")
	}

	tokenExpired := t.Expiration.Unix() > 0 && t.Expiration.Unix() < time.Now().Unix()
	tokenMatches := t.Token == token
	tokenUserEmpty := t.UserID == ""

	if tokenExpired || !tokenMatches || tokenUserEmpty {
		return "", NewAuthenticationError("invalid token")
	}

	return t.UserID, nil
}
