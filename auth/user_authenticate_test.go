package auth_test

import (
	"errors"
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserAuthenticate_ReturnsIdFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	usecase := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	id, _ := usecase.Execute("test", "test")

	assert.Equal(t, "123", id, "Should return user returned from user repo")
}

func TestUserAuthenticate_ReturnsErrFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	usecase := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	userRepo.On("GetByUsername", "test").Return(auth.User{}, errors.New("could not connect to database"))
	_, err := usecase.Execute("test", "test")

	assert.EqualError(t, err, "failed getting user: could not connect to database")
}

func TestUserAuthenticate_VerifyUserCreds_InvalidParamsErrorWhenMissingUsernamePassword(t *testing.T) {
	usecase := auth.UserAuthenticate{}
	_, err := usecase.Execute("", "")
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}
