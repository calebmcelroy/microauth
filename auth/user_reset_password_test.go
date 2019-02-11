package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUserResetPassword_BadRequestErrorOnInvaidToken(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	resetTokRepo.On("Get", "resetToken").Return(auth.ResetToken{}, nil)

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserResetPassword_ReturnErrorFromResetTokenRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	resetTokRepo.On("Get", "resetToken").Return(auth.ResetToken{}, errors.New("test error"))

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserResetPassword_ReturnBadRequestWhenPasswordInvalid(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	resetTokRepo.On("Get", "resetToken").Return(tok, nil)

	passValidator.On("Validate", "password").Return(errors.New("test error"))

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserResetPassword_ReturnErrorFromUserRepo(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	resetTokRepo.On("Get", "resetToken").Return(tok, nil)

	passValidator.On("Validate", "password").Return(nil)

	userRepo.On("Get", "userID").Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserResetPassword_ReturnErrorFromUserRepoUpdate(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	resetTokRepo.On("Get", "resetToken").Return(tok, nil)

	passValidator.On("Validate", "password").Return(nil)

	u := auth.User{}
	userRepo.On("Get", "userID").Return(u, nil)

	passHasher.On("Hash", "password").Return("passHash")

	u.PasswordHash = "passHash"
	userRepo.On("Update", u).Return(errors.New("test error"))

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserResetPassword_ReturnErrorFromResetTokenRepoDelete(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	resetTokRepo.On("Get", "resetToken").Return(tok, nil)

	passValidator.On("Validate", "password").Return(nil)

	u := auth.User{}
	userRepo.On("Get", "userID").Return(u, nil)

	passHasher.On("Hash", "password").Return("passHash")

	u.PasswordHash = "passHash"
	userRepo.On("Update", u).Return(nil)

	resetTokRepo.On("Delete", "resetTok").Return(errors.New("test error"))

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserResetPassword_ReturnNilOnSuccess(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	resetTokRepo := &mocks.ResetTokenRepo{}
	passValidator := &mocks.Validator{}
	passHasher := &mocks.Hasher{}

	tok := auth.ResetToken{
		UUID:       "resetTok",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	resetTokRepo.On("Get", "resetToken").Return(tok, nil)

	passValidator.On("Validate", "password").Return(nil)

	u := auth.User{}
	userRepo.On("Get", "userID").Return(u, nil)

	passHasher.On("Hash", "password").Return("passHash")

	u.PasswordHash = "passHash"
	userRepo.On("Update", u).Return(nil)

	resetTokRepo.On("Delete", "resetTok").Return(nil)

	usecase := auth.UserResetPassword{
		UserRepo:          userRepo,
		ResetTokenRepo:    resetTokRepo,
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("resetToken", "password")
	assert.Nil(t, err)
}
