package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUserChangeEmail_BadRequestErrorMissingUsername(t *testing.T) {
	usecase := auth.UserChangeEmail{}

	err := usecase.Execute("", "NewEmail@test.com", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangeEmail_ReturnAuthenticationErrorInvalidToken(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", "authToken").Return(auth.Token{}, nil)

	tokenAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usecase := auth.UserChangeEmail{
		TokenAuthenticate: tokenAuth,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangeEmail_AuthenticationErrorIfInvalidAuthUserPassword(t *testing.T) {
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

	usecase := auth.UserChangeEmail{
		PasswordHasher:    passHasher,
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "authToken", "authUserPassword")

	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangeEmail_ReturnsAuthorizationErrorIfCantEditUser(t *testing.T) {
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

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:         "userID",
		Email:        "test@test.com",
		Username:     "Username",
		Roles:        []string{"roleSlug"},
		PasswordHash: "passHash",
	}

	userRepo.On("Get", "userID").Return(user, nil)

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

	usecase := auth.UserChangeEmail{
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangeEmail_ReturnsBadRequestOnInvalidEmail(t *testing.T) {
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

	updatedUser := user
	updatedUser.Email = "NewEmail"

	userRepo.On("Update", updatedUser).Return(nil)

	usecase := auth.UserChangeEmail{
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("userID", "NewEmail", "authToken", "authUserPassword")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangeEmail_ReturnsUserRepoUpdateError(t *testing.T) {
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

	updatedUser := user
	updatedUser.Email = "NewEmail@test.com"

	userRepo.On("Update", updatedUser).Return(errors.New("test error"))

	usecase := auth.UserChangeEmail{
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "authToken", "authUserPassword")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangeEmail_NilOnSuccess(t *testing.T) {
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

	updatedUser := user
	updatedUser.Email = "NewEmail@test.com"

	userRepo.On("Update", updatedUser).Return(nil)

	usecase := auth.UserChangeEmail{
		TokenAuthenticate: tokenAuth,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "authToken", "authUserPassword")
	assert.Nil(t, err)
}
