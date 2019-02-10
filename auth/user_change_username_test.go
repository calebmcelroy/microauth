package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"
)

func TestUserChangeUsername_BadRequestErrorMissingUsername(t *testing.T) {
	usecase := auth.UserChangeUsername{}

	err := usecase.Execute("", "newUsername", "authToken")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangeUsername_ReturnAuthenticationErrorInvalidToken(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", "authToken").Return(auth.Token{}, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usecase := auth.UserChangeUsername{
		UsernameValidator: usernameValidator,
		TokenAuthenticate: tokenAuth,
	}

	err := usecase.Execute("Username", "newUsername", "authToken")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangeUsername_ReturnsAuthorizationErrorIfCantEditUser(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:         "userID",
		Email:        "test@test.com",
		Username:     "Username",
		Roles:        []string{"roleSlug"},
		PasswordHash: "passHash",
	}

	userRepo.On("GetByUsername", "Username").Return(user, nil)

	authUser := auth.User{
		UUID:         "userID2",
		Email:        "test2@test.com",
		Username:     "Username2",
		Roles:        []string{"roleSlug"},
		PasswordHash: "passHash",
	}
	userRepo.On("Get", "userID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "roleSlug",
			Open: true,
			CanEditUser: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserChangeUsername{
		UsernameValidator: usernameValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("Username", "newUsername", "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangeUsername_ReturnsBadRequestUsernameValidatorError(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:         "userID",
		Email:        "test@test.com",
		Username:     "Username",
		Roles:        []string{"roleSlug"},
		PasswordHash: "passHash",
	}

	userRepo.On("GetByUsername", "Username").Return(user, nil)
	userRepo.On("Get", "userID").Return(user, nil)

	usecase := auth.UserChangeUsername{
		UsernameValidator: usernameValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
	}

	err := usecase.Execute("Username", "newUsername", "authToken")
	assert.Equal(t, true, auth.IsBadRequestError(err))
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangeUsername_ReturnsUserRepoUpdateError(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.Anything).Return(nil)

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:         "userID",
		Email:        "test@test.com",
		Username:     "Username",
		Roles:        []string{"roleSlug"},
		PasswordHash: "passHash",
	}

	userRepo.On("GetByUsername", "Username").Return(user, nil)
	userRepo.On("Get", "userID").Return(user, nil)

	updatedUser := user
	updatedUser.Username = "newUsername"

	userRepo.On("Update", updatedUser).Return(errors.New("test error"))

	usecase := auth.UserChangeUsername{
		UsernameValidator: usernameValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
	}

	err := usecase.Execute("Username", "newUsername", "authToken")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangeUsername_NilOnSuccess(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.Anything).Return(nil)

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:         "userID",
		Email:        "test@test.com",
		Username:     "Username",
		Roles:        []string{"roleSlug"},
		PasswordHash: "passHash",
	}

	userRepo.On("GetByUsername", "Username").Return(user, nil)
	userRepo.On("Get", "userID").Return(user, nil)

	updatedUser := user
	updatedUser.Username = "newUsername"

	userRepo.On("Update", updatedUser).Return(nil)

	usecase := auth.UserChangeUsername{
		UsernameValidator: usernameValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
	}

	err := usecase.Execute("Username", "newUsername", "authToken")
	assert.Nil(t, err)
}
