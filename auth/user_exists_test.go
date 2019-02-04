package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestUserExists_BadRequestErrorWhenMissingUsername(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	usecase := auth.UserExists{UserRepo: userRepo}
	_, err := usecase.Execute("")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserExists_ReturnsErrorFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByUsername", mock.Anything).Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserExists{UserRepo: userRepo}
	_, err := usecase.Execute("test")

	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserExists_FalseWhenNotExists(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByUsername", mock.Anything).Return(auth.User{}, nil)

	usecase := auth.UserExists{UserRepo: userRepo}
	exists, err := usecase.Execute("test")

	assert.Nil(t, err)
	assert.Equal(t, false, exists)
}

func TestUserExists_TrueWhenExists(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByUsername", mock.Anything).Return(auth.User{Username: "test"}, nil)

	usecase := auth.UserExists{UserRepo: userRepo}
	exists, err := usecase.Execute("test")

	assert.Nil(t, err)
	assert.Equal(t, true, exists)
}
