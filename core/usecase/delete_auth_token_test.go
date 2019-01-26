package usecase

import (
	"github.com/pkg/errors"
	"testing"
	"time"

	"github.com/calebmcelroy/tradelead-auth/core/boundary/mocks"
	"github.com/calebmcelroy/tradelead-auth/core/entity"
	"github.com/stretchr/testify/assert"
)

func TestDeletesTokenWhenAuthAndExists(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := entity.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := entity.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Delete", deleteToken.Token).Return(nil)
	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	err := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Nil(t, err)
}

func TestReturnAuthenticationErrorWhenAuthNotFound(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := "deleteToken"
	authToken := "authToken"

	tokenRepo.On("Get", authToken).Return(entity.Token{}, nil)

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken, authToken)
	assert.Equal(t, true, IsAuthenticationError(e))
}

func TestAuthorizationErrorWhenAuthTokenAndDeleteTokenUserDontMatch(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := entity.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := entity.Token{
		Token:      "auth",
		UserID:     "1234",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, IsAuthorizationError(e))
}

func TestAuthenticationErrorWhenAuthExpired(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := entity.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := entity.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(-time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, IsAuthenticationError(e))
}

func TestNotFoundErrorWhenDeleteTokenDoesntExist(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := entity.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := entity.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(entity.Token{}, nil)
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.Equal(t, true, IsNotFoundError(e))
}

func TestWrapErrorFromTokenRepoOnDeleteGetError(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := entity.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := entity.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", deleteToken.Token).Return(entity.Token{}, errors.New("test error"))
	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.EqualError(t, e, "retrieving delete token failed: test error")
}

func TestWrapErrorFromTokenRepoOnDeleteError(t *testing.T) {
	tokenRepo := &mocks.TokenRepo{}

	deleteToken := entity.Token{
		Token:      "delete",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	authToken := entity.Token{
		Token:      "auth",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}

	tokenRepo.On("Get", authToken.Token).Return(authToken, nil)
	tokenRepo.On("Get", deleteToken.Token).Return(deleteToken, nil)
	tokenRepo.On("Delete", deleteToken.Token).Return(errors.New("test error"))

	usecase := DeleteAuthToken{
		VerifyAuthToken: VerifyAuthToken{tokenRepo},
		TokenRepo:       tokenRepo,
	}

	e := usecase.Execute(deleteToken.Token, authToken.Token)
	assert.EqualError(t, e, "error deleting token: test error")
}
