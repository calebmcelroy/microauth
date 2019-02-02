package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenDelete_DeletesTokenWhenAuthAndExists(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := auth.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := auth.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Delete", deleteToken.Token).Return(nil)
	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	err := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Nil(t, err)
}

func TestTokenDelete_ReturnAuthenticationErrorWhenAuthNotFound(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := "deleteToken"
	authToken := "authToken"

	tokenRepo.On("Get", authToken).Return(auth.Token{}, nil)

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	e := usecase.Execute(deleteToken, authToken)
	assert.Equal(t, true, auth.IsAuthenticationError(e))
}

func TestTokenDelete_AuthorizationErrorWhenAuthTokenAndDeleteTokenUserDontMatch(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := auth.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := auth.Token{
		Token:      "auth",
		UserID:     "1234",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, auth.IsAuthorizationError(e))
}

func TestTokenDelete_AuthenticationErrorWhenAuthExpired(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := auth.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := auth.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(-time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, auth.IsAuthenticationError(e))
}

func TestTokenDelete_NotFoundErrorWhenDeleteTokenDoesntExist(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := auth.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := auth.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(auth.Token{}, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, auth.IsNotFoundError(e))
}

func TestTokenDelete_WrapErrorFromTokenRepoOnDeleteGetError(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := auth.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := auth.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(auth.Token{}, errors.New("test error"))
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.EqualError(t, e, "retrieving delete auth failed: test error")
}

func TestTokenDelete_WrapErrorFromTokenRepoOnDeleteError(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := auth.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := auth.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)
	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Delete", deleteToken.Token).Return(errors.New("test error"))

	usecase := auth.TokenDelete{
		TokenAuthenticate: auth.TokenAuthenticate{tokenRepo},
		TokenRepo:         tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.EqualError(t, e, "error deleting auth: test error")
}
