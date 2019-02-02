package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGetUserTokens_ReturnsTokensFromRepo(t *testing.T) {
	tokens := []auth.Token{
		{Token: "123", UserID: "123"},
		{Token: "234", UserID: "123"},
		{Token: "345", UserID: "123"},
		{Token: "456", UserID: "123"},
	}

	authToken := "authToken"
	userID := "123"

	tr := &mocks.TokenRepo{}
	tk := auth.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", authToken).Return(tk, nil)
	tr.On("GetByUser", userID).Return(tokens, nil)

	usecase := auth.GetUserTokens{
		TokenRepo:         tr,
		TokenAuthenticate: auth.TokenAuthenticate{TokenRepo: tr},
	}

	tokens2, _ := usecase.Execute(authToken)
	assert.Equal(t, tokens, tokens2)
}

func TestGetUserTokens_AuthenticationErrorWhenAuthTokenInvalid(t *testing.T) {
	authToken := "authToken"

	tr := &mocks.TokenRepo{}
	tr.On("Get", authToken).Return(auth.Token{}, nil)

	usecase := auth.GetUserTokens{
		TokenRepo:         tr,
		TokenAuthenticate: auth.TokenAuthenticate{TokenRepo: tr},
	}

	_, err := usecase.Execute(authToken)
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestGetUserTokens_InvalidParamsErrorWhenMissingAuthToken(t *testing.T) {
	usecase := auth.GetUserTokens{}

	_, err := usecase.Execute("")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestGetUserTokens_WrapsErrorFromTokenRepo(t *testing.T) {
	authToken := "authToken"
	userID := "123"

	tr := &mocks.TokenRepo{}
	tk := auth.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", authToken).Return(tk, nil)
	tr.On("GetByUser", userID).Return(nil, errors.New("test error"))

	usecase := auth.GetUserTokens{
		TokenRepo:         tr,
		TokenAuthenticate: auth.TokenAuthenticate{TokenRepo: tr},
	}

	_, err := usecase.Execute("authToken")
	assert.EqualError(t, err, "failed getting tokens: test error")
}
