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

func TestUserChangePassword_BadRequestErrorMissingUsername(t *testing.T) {
	usecase := auth.UserChangePassword{}

	err := usecase.Execute("", "Password", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangePassword_ReturnAuthenticationErrorInvalidToken(t *testing.T) {
	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", "authToken").Return(auth.Token{}, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		TokenAuthenticate: tokenAuth,
	}

	err := usecase.Execute("Username", "Password", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangePassword_AuthenticationErrorIfInvalidAuthUserPassword(t *testing.T) {
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

	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(nil)

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:         "userID",
		Email:        "test@test.com",
		Username:     "Username",
		Roles:        []string{"roleSlug"},
		PasswordHash: "test",
	}

	userRepo.On("GetByUsername", "Username").Return(user, nil)
	userRepo.On("Get", "userID").Return(user, nil)

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "authUserPassword").Return("invalidPass")

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		PasswordHasher:    passHasher,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
	}

	err := usecase.Execute("Username", "Password", "authToken", "authUserPassword")

	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangePassword_ReturnsAuthorizationErrorIfCantEditUser(t *testing.T) {
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

	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

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

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "authUserPassword").Return("passHash")

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

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("Username", "Password", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangePassword_ReturnsPasswordValidatorError(t *testing.T) {
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

	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

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

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "authUserPassword").Return("passHash")

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("Username", "Password", "authToken", "authUserPassword")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangePassword_ReturnsUserRepoUpdateError(t *testing.T) {
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

	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(nil)

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

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "authUserPassword").Return("passHash")

	passHasher.On("Hash", "Password").Return("newPassHash")
	updatedUser := user
	updatedUser.PasswordHash = "newPassHash"

	userRepo.On("Update", updatedUser).Return(errors.New("test error"))

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("Username", "Password", "authToken", "authUserPassword")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangePassword_NilOnSuccess(t *testing.T) {
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

	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(nil)

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

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "authUserPassword").Return("passHash")

	passHasher.On("Hash", "Password").Return("newPassHash")
	updatedUser := user
	updatedUser.PasswordHash = "newPassHash"

	userRepo.On("Update", updatedUser).Return(nil)

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("Username", "Password", "authToken", "authUserPassword")
	assert.Nil(t, err)
}
