package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestUserEmailExists_BadRequestErrorWhenMissingEmail(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	usecase := auth.UserEmailExists{UserRepo: userRepo}
	_, err := usecase.Execute("")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserEmailExists_ReturnsErrorFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByEmail", mock.Anything).Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserEmailExists{UserRepo: userRepo}
	_, err := usecase.Execute("test@test.com")

	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserEmailExists_FalseWhenNotExists(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByEmail", mock.Anything).Return(auth.User{}, nil)

	usecase := auth.UserEmailExists{UserRepo: userRepo}
	exists, err := usecase.Execute("test@test.com")

	assert.Nil(t, err)
	assert.Equal(t, false, exists)
}

func TestUserEmailExists_TrueWhenExists(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByEmail", mock.Anything).Return(auth.User{Email: "test@test.com"}, nil)

	usecase := auth.UserEmailExists{UserRepo: userRepo}
	exists, err := usecase.Execute("test@test.com")

	assert.Nil(t, err)
	assert.Equal(t, true, exists)
}
