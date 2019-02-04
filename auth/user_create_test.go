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

func createUserObject() auth.User {
	return auth.User{
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{"admin"},
	}
}

func TestUserCreate_BadRequestWhenUserMissingEmail(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Email = ""
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserCreate_BadRequestWhenUserMissingUsername(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Username = ""
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserCreate_BadRequestWhenUserMissingRole(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Roles = nil
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserCreate_BadRequestWhenEmailInvalid(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Email = "invalidemail"
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserCreate_BadRequestWhenUsernameInvalid(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.AnythingOfType("string")).Return(errors.New("test error"))

	usecase := auth.UserCreate{
		UsernameValidator: usernameValidator,
	}

	u := createUserObject()
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserCreate_BadRequestWhenPasswordInvalid(t *testing.T) {
	userValidator := &mocks.Validator{}
	userValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	passValidator := &mocks.Validator{}
	passValidator.On("Validate", mock.AnythingOfType("string")).Return(errors.New("test error"))

	usecase := auth.UserCreate{
		UsernameValidator: userValidator,
		PasswordValidator: passValidator,
	}

	u := createUserObject()
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserCreate_AnonymousReturnAuthorizationErrorWhenCreateWithRoleNotOpen(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	passwordValidator := &mocks.Validator{}
	passwordValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "test",
			Open: false,
		},
	}

	usecase := auth.UserCreate{
		UsernameValidator: usernameValidator,
		PasswordValidator: passwordValidator,
		RoleConfigs:       roleConfigs,
	}

	u := createUserObject()
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserCreate_AuthorizationErrorWhenAuthUserCannotCreateRoleInNewUser(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	passwordValidator := &mocks.Validator{}
	passwordValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	roleSlug := "test"
	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanCreateUser: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	authToken := "authToken"
	userID := "userID"

	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", authToken).Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     userID,
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", userID).Return(user, nil)

	usecase := auth.UserCreate{
		UsernameValidator: usernameValidator,
		PasswordValidator: passwordValidator,
		RoleConfigs:       roleConfigs,
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}

	u := createUserObject()
	u.Roles = append(u.Roles, "test")
	_, err := usecase.Execute(u, "password", authToken)
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserCreate_WrapUserInsertError(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	passwordValidator := &mocks.Validator{}
	passwordValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	roleSlug := "test"
	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: true,
			CanCreateUser: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	authToken := "authToken"
	userID := "userID"

	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", authToken).Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     userID,
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", userID).Return(user, nil)
	userRepo.On("Insert", mock.Anything).Return(errors.New("test error"))

	usecase := auth.UserCreate{
		UsernameValidator: usernameValidator,
		PasswordValidator: passwordValidator,
		RoleConfigs:       roleConfigs,
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}

	u := createUserObject()
	u.Roles = append(u.Roles, "test")

	ID, err := usecase.Execute(u, "password", authToken)

	assert.Equal(t, true, ID == "")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserCreate_AuthUserCanCreateRoleInNewUser(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	passwordValidator := &mocks.Validator{}
	passwordValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	roleSlug := "test"
	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanCreateUser: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	authToken := "authToken"
	userID := "userID"

	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", authToken).Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     userID,
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	userRepo.On("Get", userID).Return(user, nil)
	userRepo.On("Insert", mock.Anything).Return(nil)

	usecase := auth.UserCreate{
		UsernameValidator: usernameValidator,
		PasswordValidator: passwordValidator,
		RoleConfigs:       roleConfigs,
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}

	u := createUserObject()
	u.Roles = append(u.Roles, "test")

	ID, err := usecase.Execute(u, "password", authToken)
	assert.NotEqual(t, "", ID)
	assert.Nil(t, err)
}

func TestUserCreate_AnonymousUserCanCreateOpenRoleUser(t *testing.T) {
	usernameValidator := &mocks.Validator{}
	usernameValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	passwordValidator := &mocks.Validator{}
	passwordValidator.On("Validate", mock.AnythingOfType("string")).Return(nil)

	roleSlug := "test"
	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: true,
			CanCreateUser: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	tokRepo := &mocks.TokenRepo{}

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	userRepo := &mocks.UserRepo{}
	userRepo.On("Insert", mock.Anything).Return(nil)

	usecase := auth.UserCreate{
		UsernameValidator: usernameValidator,
		PasswordValidator: passwordValidator,
		RoleConfigs:       roleConfigs,
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}

	u := createUserObject()
	u.Roles = []string{roleSlug}

	ID, err := usecase.Execute(u, "password", "")

	assert.NotEqual(t, "", ID)
	assert.Nil(t, err)
}
