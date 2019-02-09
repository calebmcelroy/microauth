package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestUserSendPasswordReset_BadRequestErrorWhenEmailEmpty(t *testing.T) {
	usecase := auth.UserSendPasswordReset{}
	err := usecase.Execute("")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserSendPasswordReset_EmptyResetTokWhenEmailNotFound(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByEmail", "test@test.com").Return(auth.User{}, nil)

	passResetMailer := &mocks.PasswordResetMailer{}
	passResetMailer.On("Send", "test@test.com", "").Return(nil)

	usecase := auth.UserSendPasswordReset{
		UserRepo:            userRepo,
		PasswordResetMailer: passResetMailer,
	}
	err := usecase.Execute("test@test.com")
	passResetMailer.AssertCalled(t, "Send", "test@test.com", "")
	assert.Nil(t, err)
}

func TestUserSendPasswordReset_ReturnErrorFromUserRepoGetByEmail(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByEmail", "test@test.com").Return(auth.User{}, errors.New("test error"))

	passResetMailer := &mocks.PasswordResetMailer{}
	passResetMailer.On("Send", "test@test.com", "").Return(nil)

	usecase := auth.UserSendPasswordReset{
		UserRepo:            userRepo,
		PasswordResetMailer: passResetMailer,
	}
	err := usecase.Execute("test@test.com")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserSendPasswordReset_ReturnErrorFromPassResetMailer(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	userRepo.On("GetByEmail", "test@test.com").Return(auth.User{}, nil)

	passResetMailer := &mocks.PasswordResetMailer{}
	passResetMailer.On("Send", "test@test.com", "").Return(errors.New("test error"))

	usecase := auth.UserSendPasswordReset{
		UserRepo:            userRepo,
		PasswordResetMailer: passResetMailer,
	}
	err := usecase.Execute("test@test.com")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserSendPasswordReset_ReturnErrorFromResetTokenRepoInsert(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	user := auth.User{
		UUID:  "userID",
		Email: "test@test.com",
	}
	userRepo.On("GetByEmail", "test@test.com").Return(user, nil)

	matchUUIDNotEmpty := mock.MatchedBy(func(UUID string) bool { return UUID != "" })

	resetTokRepo := &mocks.ResetTokenRepo{}
	resetTokRepo.On("Insert", matchUUIDNotEmpty, "userID").Return(errors.New("test error"))

	passResetMailer := &mocks.PasswordResetMailer{}
	passResetMailer.On("Send", "test@test.com", matchUUIDNotEmpty).Return(nil)

	usecase := auth.UserSendPasswordReset{
		UserRepo:            userRepo,
		PasswordResetMailer: passResetMailer,
		ResetTokenRepo:      resetTokRepo,
	}
	err := usecase.Execute("test@test.com")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserSendPasswordReset_ReturnErrorFromPassResetMailerOnEmailFound(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	user := auth.User{
		UUID:  "userID",
		Email: "test@test.com",
	}
	userRepo.On("GetByEmail", "test@test.com").Return(user, nil)

	matchUUIDNotEmpty := mock.MatchedBy(func(UUID string) bool { return UUID != "" })

	resetTokRepo := &mocks.ResetTokenRepo{}
	resetTokRepo.On("Insert", matchUUIDNotEmpty, "userID").Return(nil)

	passResetMailer := &mocks.PasswordResetMailer{}
	passResetMailer.On("Send", "test@test.com", matchUUIDNotEmpty).Return(errors.New("test error"))

	usecase := auth.UserSendPasswordReset{
		UserRepo:            userRepo,
		PasswordResetMailer: passResetMailer,
		ResetTokenRepo:      resetTokRepo,
	}
	err := usecase.Execute("test@test.com")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserSendPasswordReset_SendResetTokWhenEmailFound(t *testing.T) {
	userRepo := &mocks.UserRepo{}

	user := auth.User{
		UUID:  "userID",
		Email: "test@test.com",
	}
	userRepo.On("GetByEmail", "test@test.com").Return(user, nil)

	matchUUIDNotEmpty := mock.MatchedBy(func(UUID string) bool { return UUID != "" })

	resetTokRepo := &mocks.ResetTokenRepo{}
	resetTokRepo.On("Insert", matchUUIDNotEmpty, "userID").Return(nil)

	passResetMailer := &mocks.PasswordResetMailer{}
	passResetMailer.On("Send", "test@test.com", matchUUIDNotEmpty).Return(nil)

	usecase := auth.UserSendPasswordReset{
		UserRepo:            userRepo,
		PasswordResetMailer: passResetMailer,
		ResetTokenRepo:      resetTokRepo,
	}
	err := usecase.Execute("test@test.com")
	resetTokRepo.AssertCalled(t, "Insert", matchUUIDNotEmpty, "userID")
	passResetMailer.AssertCalled(t, "Send", "test@test.com", matchUUIDNotEmpty)
	assert.Nil(t, err)
}
