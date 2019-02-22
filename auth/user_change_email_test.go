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

	err := usecase.Execute("", "NewEmail@test.com", "secureGrant")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangeEmail_ReturnAuthenticationErrorInvalidToken(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

	usecase := auth.UserChangeEmail{
		GrantInfo: grantInfo,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "secureGrant")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserChangeEmail_ReturnAuthorizationErrorUnsecureGrant(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}
	g := auth.Grant{
		UUID:     "secureGrant",
		UserID:   "userID",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   false,
		Uses:     3,
		UseLimit: 4,
	}
	grantRepo.On("Get", "secureGrant").Return(g, nil)
	grantInfo := auth.GrantInfo{GrantRepo: grantRepo}

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
		PasswordHasher: passHasher,
		GrantInfo:      grantInfo,
		UserRepo:       userRepo,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "secureGrant")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangeEmail_ReturnsAuthorizationErrorIfCantEditUser(t *testing.T) {
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
		GrantInfo:      grantInfo,
		UserRepo:       userRepo,
		PasswordHasher: passHasher,
		RoleConfigs:    roleConfigs,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "secureGrant")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserChangeEmail_ReturnsBadRequestOnInvalidEmail(t *testing.T) {
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
		GrantInfo:      grantInfo,
		UserRepo:       userRepo,
		PasswordHasher: passHasher,
	}

	err := usecase.Execute("userID", "NewEmail", "secureGrant")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserChangeEmail_ReturnsUserRepoUpdateError(t *testing.T) {
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
		GrantInfo:      grantInfo,
		UserRepo:       userRepo,
		PasswordHasher: passHasher,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "secureGrant")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserChangeEmail_NilOnSuccess(t *testing.T) {
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
		GrantInfo:      grantInfo,
		UserRepo:       userRepo,
		PasswordHasher: passHasher,
	}

	err := usecase.Execute("userID", "NewEmail@test.com", "secureGrant")
	assert.Nil(t, err)
}
