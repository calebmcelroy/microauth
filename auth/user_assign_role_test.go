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

func TestUserAssignRole_AuthorizationErrorWhenUserRoleConfigUnauthorized(t *testing.T) {
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
		UUID: "123",
	}
	userRepo.On("Get", "123").Return(user, nil)

	roleSlug := "test"
	newRoleSlug := "newRole"

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
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "New Role",
			Slug: newRoleSlug,
			Open: false,
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserAssignRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", newRoleSlug, "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserAssignRole_ErrorWhenUserRepoUpdateError(t *testing.T) {
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
		UUID: "123",
	}
	userRepo.On("Get", "123").Return(user, nil)

	roleSlug := "test"
	newRoleSlug := "newRole"

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
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "New Role",
			Slug: newRoleSlug,
			Open: false,
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	userRepo.On("Update", mock.Anything).Return(errors.New("test error"))

	usecase := auth.UserAssignRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", newRoleSlug, "authToken")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserAssignRole_ErrorWhenRoleAlreadyExists(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	newRoleSlug := "newRole"
	user := auth.User{
		UUID:  "123",
		Roles: []string{newRoleSlug},
	}
	userRepo.On("Get", "123").Return(user, nil)

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
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "New Role",
			Slug: newRoleSlug,
			Open: false,
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	usecase := auth.UserAssignRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", newRoleSlug, "authToken")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserAssignRole_AuthorizationErrorWhenRoleAlreadyExistsButNotAuthorized(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}

	newRoleSlug := "newRole"
	user := auth.User{
		UUID:  "123",
		Roles: []string{newRoleSlug},
	}
	userRepo.On("Get", "123").Return(user, nil)

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
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "New Role",
			Slug: newRoleSlug,
			Open: false,
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserAssignRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", newRoleSlug, "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserAssignRole_UpdatesUserWithRole(t *testing.T) {
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
		UUID: "123",
	}
	userRepo.On("Get", "123").Return(user, nil)

	roleSlug := "test"
	newRoleSlug := "newRole"

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
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
		{
			Name: "New Role",
			Slug: newRoleSlug,
			Open: false,
			CanAssignUserRole: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	user.Roles = append(user.Roles, newRoleSlug)
	userRepo.On("Update", user).Return(nil)

	usecase := auth.UserAssignRole{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	err := usecase.Execute("123", newRoleSlug, "authToken")
	assert.Nil(t, err)
}
