package usecase

import (
	"errors"
	"testing"
	"time"

	"github.com/calebmcelroy/tradelead-auth/core/boundary/mocks"
	"github.com/calebmcelroy/tradelead-auth/core/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestInvalidParamsErrorWhenMissingUsernamePassword(t *testing.T) {

	usecase := CreateAuthToken{}
	_, err := usecase.Execute("", "", false)
	assert.Equal(t, true, IsInvalidParamsError(err))

}

func TestInsertsToken(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	usecase.Execute("test", "test", false)

	tokenRepo.AssertNumberOfCalls(t, "Insert", 1)
}

func TestAuthenticationErrorWhenInvalidCreds(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("", NewAuthenticationError("Invalid credentials"))

	_, err := usecase.Execute("test", "test", false)

	tokenRepo.AssertNumberOfCalls(t, "Insert", 0)

	assert.Equal(t, true, IsAuthenticationError(err))
}

func TestReturnsWrappedErrorWhenTokenRepoInsertError(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(errors.New("could not connect to db"))

	_, err := usecase.Execute("test", "test", false)

	assert.EqualError(t, err, "insert token failed: could not connect to db")
}

func TestEmptyTokenWhenTokenRepoError(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(errors.New("could not connect to db"))

	token, _ := usecase.Execute("test", "test", false)

	assert.Equal(t, entity.Token{}, token)
}

func TestForCorrectUser(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	token, err := usecase.Execute("test", "test", false)

	assert.Nil(t, err)
	assert.Equal(t, "123", token.UserID)
}

func TestForToken(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	token, err := usecase.Execute("test", "test", false)

	assert.Nil(t, err)
	assert.NotEmpty(t, token.Token)
}

func TestFor1DayExp(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	token, _ := usecase.Execute("test", "test", false)

	expected := time.Now().Add(time.Hour * 24)
	assert.Equal(t, expected.Unix(), token.Expiration.Unix())
}

func TestFor30DayExpOnRemember(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	verifyUser := VerifyUserCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := CreateAuthToken{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	token, _ := usecase.Execute("test", "test", true)

	expected := time.Now().Add(time.Hour * 24 * 30)
	assert.Equal(t, expected.Unix(), token.Expiration.Unix())
}
