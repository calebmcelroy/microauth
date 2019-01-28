package user

import (
	"errors"
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/calebmcelroy/tradelead-auth/user/mocks"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReturnsIdFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	usecase := VerifyCreds{
		UserRepo: userRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	id, _ := usecase.Execute("test", "test")

	assert.Equal(t, "123", id, "Should return user returned from user repo")
}

func TestReturnsErrFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	usecase := VerifyCreds{
		UserRepo: userRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("", errors.New("could not connect to database"))
	_, err := usecase.Execute("test", "test")

	assert.EqualError(t, err, "error verifying user credentials: could not connect to database")
}

func TestReturnsAuthenticationErrFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	usecase := VerifyCreds{
		UserRepo: userRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("", errs.NewAuthenticationError("invalid username and password"))
	_, err := usecase.Execute("test", "test")

	assert.Equal(t, true, errs.IsAuthenticationError(err))
}

func TestVerifyUserCreds_InvalidParamsErrorWhenMissingUsernamePassword(t *testing.T) {
	usecase := VerifyCreds{}
	_, err := usecase.Execute("", "")
	assert.Equal(t, true, errs.IsInvalidParamsError(err))
}
