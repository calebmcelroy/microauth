package token

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/pkg/errors"
)

type ListByUser struct {
	TokenRepo   TokenRepo
	VerifyToken Verify
}

func (u ListByUser) Execute(authToken string) ([]Token, error) {
	if authToken == "" {
		return nil, errs.NewAuthenticationError("missing auth token")
	}

	userID, err := u.VerifyToken.Execute(authToken)
	if err != nil {
		return nil, err
	}

	tokens, err := u.TokenRepo.GetByUser(userID)
	return tokens, errors.Wrap(err, "failed getting tokens")
}
