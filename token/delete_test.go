package token_test

import (
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/calebmcelroy/tradelead-auth/token"
	"github.com/calebmcelroy/tradelead-auth/token/mocks"
	"github.com/pkg/errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeletesTokenWhenAuthAndExists(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := token.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := token.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Delete", deleteToken.Token).Return(nil)
	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	err := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Nil(t, err)
}

func TestReturnAuthenticationErrorWhenAuthNotFound(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := "deleteToken"
	authToken := "authToken"

	tokenRepo.On("Get", authToken).Return(token.Token{}, nil)

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken, authToken)
	assert.Equal(t, true, errs.IsAuthenticationError(e))
}

func TestAuthorizationErrorWhenAuthTokenAndDeleteTokenUserDontMatch(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := token.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := token.Token{
		Token:      "auth",
		UserID:     "1234",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, errs.IsAuthorizationError(e))
}

func TestAuthenticationErrorWhenAuthExpired(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := token.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := token.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(-time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, errs.IsAuthenticationError(e))
}

func TestNotFoundErrorWhenDeleteTokenDoesntExist(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := token.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := token.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(token.Token{}, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, errs.IsNotFoundError(e))
}

func TestWrapErrorFromTokenRepoOnDeleteGetError(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := token.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := token.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(token.Token{}, errors.New("test error"))
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.EqualError(t, e, "retrieving delete token failed: test error")
}

func TestWrapErrorFromTokenRepoOnDeleteError(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := token.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := token.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)
	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Delete", deleteToken.Token).Return(errors.New("test error"))

	usecase := token.Delete{
		VerifyAuthToken: token.Verify{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.EqualError(t, e, "error deleting token: test error")
}
