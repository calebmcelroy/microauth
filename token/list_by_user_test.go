package token_test

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/calebmcelroy/tradelead-auth/token"
	"github.com/calebmcelroy/tradelead-auth/token/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestListByUser_ReturnsTokensFromRepo(t *testing.T) {
	tokens := []token.Token{
		{Token: "123", UserID: "123"},
		{Token: "234", UserID: "123"},
		{Token: "345", UserID: "123"},
		{Token: "456", UserID: "123"},
	}

	authToken := "authToken"
	userID := "123"

	tr := &mocks.TokenRepo{}
	tk := token.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", authToken).Return(tk, nil)
	tr.On("GetByUser", userID).Return(tokens, nil)

	usecase := token.ListByUser{
		TokenRepo:   tr,
		VerifyToken: token.Verify{TokenRepo: tr},
	}

	tokens2, _ := usecase.Execute(authToken)
	assert.Equal(t, tokens, tokens2)
}

func TestListByUser_AuthenticationErrorWhenAuthTokenInvalid(t *testing.T) {
	authToken := "authToken"

	tr := &mocks.TokenRepo{}
	tr.On("Get", authToken).Return(token.Token{}, nil)

	usecase := token.ListByUser{
		TokenRepo:   tr,
		VerifyToken: token.Verify{TokenRepo: tr},
	}

	_, err := usecase.Execute(authToken)
	assert.Equal(t, true, errs.IsAuthenticationError(err))
}

func TestListByUser_InvalidParamsErrorWhenMissingAuthToken(t *testing.T) {
	usecase := token.ListByUser{}

	_, err := usecase.Execute("")
	assert.Equal(t, true, errs.IsAuthenticationError(err))
}

func TestListByUser_WrapsErrorFromTokenRepo(t *testing.T) {
	authToken := "authToken"
	userID := "123"

	tr := &mocks.TokenRepo{}
	tk := token.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", authToken).Return(tk, nil)
	tr.On("GetByUser", userID).Return(nil, errors.New("test error"))

	usecase := token.ListByUser{
		TokenRepo:   tr,
		VerifyToken: token.Verify{TokenRepo: tr},
	}

	_, err := usecase.Execute("authToken")
	assert.EqualError(t, err, "failed getting tokens: test error")
}
