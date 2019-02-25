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

	err := usecase.Execute("", "Password", "secureGrant")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangePassword_ReturnAuthenticationErrorInvalidGrant(t *testing.T) {
	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		GrantInfo:         grantInfo,
	}

	err := usecase.Execute("userID", "Password", "secureGrant")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangePassword_ReturnAuthorizationErrorUnsecureGrant(t *testing.T) {
	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.Anything).Return(errors.New("test error"))

	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", "authToken").Return(auth.Token{}, nil)

	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{
		UUID:     "secureGrant",
		UserID:   "userID2",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   false,
		Uses:     3,
		UseLimit: 4,
	}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

	usecase := auth.UserChangePassword{
		PasswordValidator: passValidator,
		GrantInfo:         grantInfo,
	}

	err := usecase.Execute("userID", "Password", "secureGrant")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangePassword_ReturnsAuthorizationErrorIfCantEditUser(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{
		UUID:     "secureGrant",
		UserID:   "userID2",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
	}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

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
		GrantInfo:         grantInfo,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("userID", "Password", "secureGrant")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangePassword_ReturnsBadRequestPasswordValidatorError(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{
		UUID:     "secureGrant",
		UserID:   "userID",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
	}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

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
		GrantInfo:         grantInfo,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("userID", "Password", "secureGrant")
	assert.Equal(t, true, auth.IsBadRequestError(err))
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangePassword_ReturnsUserRepoUpdateError(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{
		UUID:     "secureGrant",
		UserID:   "userID",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
	}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

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
		GrantInfo:         grantInfo,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("userID", "Password", "secureGrant")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangePassword_NilOnSuccess(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{
		UUID:     "secureGrant",
		UserID:   "userID",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
	}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

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
		GrantInfo:         grantInfo,
		UserRepo:          userRepo,
		PasswordHasher:    passHasher,
	}

	err := usecase.Execute("userID", "Password", "secureGrant")
	assert.Nil(t, err)
}
