package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUserInfoByResetToken_BadRequestErrorWhenTokenIsEmpty(t *testing.T) {
	tokResetRepo := &mocks.ResetTokenRepo{}
	tokResetRepo.On("Get", "resetTok").Return(auth.ResetToken{}, nil)

	userRepo := &mocks.UserRepo{}

	usecase := auth.UserInfoByResetToken{
		ResetTokenRepo: tokResetRepo,
		UserRepo:       userRepo,
	}

	_, err := usecase.Execute("resetTok")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserInfoByResetToken_BadRequestErrorWhenTokenIsExpired(t *testing.T) {
	tokResetRepo := &mocks.ResetTokenRepo{}
	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(-time.Hour),
	}
	tokResetRepo.On("Get", "resetTok").Return(tok, nil)

	userRepo := &mocks.UserRepo{}

	usecase := auth.UserInfoByResetToken{
		ResetTokenRepo: tokResetRepo,
		UserRepo:       userRepo,
	}

	_, err := usecase.Execute("resetTok")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserInfoByResetToken_ReturnErrorFromResetTokenRepo(t *testing.T) {
	tokResetRepo := &mocks.ResetTokenRepo{}
	tokResetRepo.On("Get", "resetTok").Return(auth.ResetToken{}, errors.New("test error"))

	userRepo := &mocks.UserRepo{}

	usecase := auth.UserInfoByResetToken{
		ResetTokenRepo: tokResetRepo,
		UserRepo:       userRepo,
	}

	_, err := usecase.Execute("resetTok")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserInfoByResetToken_ReturnErrorFromUserRepo(t *testing.T) {
	tokResetRepo := &mocks.ResetTokenRepo{}
	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokResetRepo.On("Get", "resetTok").Return(tok, nil)

	userRepo := &mocks.UserRepo{}
	userRepo.On("Get", tok.UserID).Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserInfoByResetToken{
		ResetTokenRepo: tokResetRepo,
		UserRepo:       userRepo,
	}

	_, err := usecase.Execute("resetTok")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserInfoByResetToken_ReturnUserRepoFromRepo(t *testing.T) {
	tokResetRepo := &mocks.ResetTokenRepo{}
	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokResetRepo.On("Get", "resetTok").Return(tok, nil)

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     tok.UUID,
		Username: "test",
		Email:    "test@test.com",
	}
	userRepo.On("Get", tok.UserID).Return(user, nil)

	usecase := auth.UserInfoByResetToken{
		ResetTokenRepo: tokResetRepo,
		UserRepo:       userRepo,
	}

	u, err := usecase.Execute("resetTok")
	assert.Nil(t, err)
	assert.Equal(t, user, u)
}
