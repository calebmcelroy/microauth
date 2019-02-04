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

func TestUserRemoveRole_AuthorizationErrorWhenUserRoleConfigUnauthorized(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	user := auth.User{
		Username: "123",
	}
	userRepo.On("GetByUsername", "123").Return(user, nil)

	roleSlug := "test"
	removeRoleSlug := "removeRole"

	authUser := auth.User{
		UUID:     "userID",
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", "userID").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "Remove Role",
			Slug: removeRoleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserRemoveRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", removeRoleSlug, "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserRemoveRole_ErrorWhenUserRepoUpdateError(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	removeRoleSlug := "removeRole"
	user := auth.User{
		Username: "123",
		Roles:    []string{removeRoleSlug},
	}
	userRepo.On("GetByUsername", "123").Return(user, nil)

	roleSlug := "test"

	authUser := auth.User{
		UUID:     "userID",
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", "userID").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "Remove Role",
			Slug: removeRoleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	userRepo.On("Update", mock.Anything).Return(errors.New("test error"))

	usecase := auth.UserRemoveRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", removeRoleSlug, "authToken")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserRemoveRole_ErrorWhenRoleDoesntExist(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	removeRoleSlug := "newRole"
	user := auth.User{
		Username: "123",
		Roles:    []string{},
	}
	userRepo.On("GetByUsername", "123").Return(user, nil)

	roleSlug := "test"

	authUser := auth.User{
		UUID:     "userID",
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", "userID").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "New Role",
			Slug: removeRoleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	usecase := auth.UserRemoveRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", removeRoleSlug, "authToken")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserRemoveRole_AuthorizationErrorWhenRoleDoesntExistButNotAuthorized(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	removeRoleSlug := "removeRole"
	user := auth.User{
		Username: "123",
		Roles:    []string{},
	}
	userRepo.On("GetByUsername", "123").Return(user, nil)

	roleSlug := "test"

	authUser := auth.User{
		UUID:     "userID",
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", "userID").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "Remove Role",
			Slug: removeRoleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserRemoveRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", removeRoleSlug, "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserRemoveRole_UpdatesUserWithRole(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	removeRoleSlug := "removeRole"

	user := auth.User{
		Username: "123",
		Roles:    []string{"firstRole", removeRoleSlug, "secondRole"},
	}
	userRepo.On("GetByUsername", "123").Return(user, nil)

	roleSlug := "test"

	authUser := auth.User{
		UUID:     "userID",
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", "userID").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "Remove Role",
			Slug: removeRoleSlug,
			Open: false,
			CanRemoveUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	user.Roles = []string{"firstRole", "secondRole"}
	userRepo.On("Update", user).Return(nil)

	usecase := auth.UserRemoveRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", removeRoleSlug, "authToken")
	assert.Nil(t, err)
}
