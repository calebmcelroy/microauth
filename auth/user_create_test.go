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

func TestUserCreate_InvalidParamsWhenUserMissingEmail(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Email = ""
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}

func TestUserCreate_InvalidParamsWhenUserMissingUsername(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Username = ""
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}

func TestUserCreate_InvalidParamsWhenUserMissingRole(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Roles = nil
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}

func TestUserCreate_InvalidParamsWhenEmailInvalid(t *testing.T) {
	usecase := auth.UserCreate{}

	u := createUserObject()
	u.Email = "invalidemail"
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}

func TestUserCreate_InvalidParamsWhenUsernameInvalid(t *testing.T) {
	vd := &mocks.Validator{}
	vd.On("Validate", mock.AnythingOfType("string")).Return(errors.New("test error"))

	usecase := auth.UserCreate{
		UsernameValidator: vd,
	}

	u := createUserObject()
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}

func TestUserCreate_InvalidParamsWhenPasswordInvalid(t *testing.T) {
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
	assert.Equal(t, true, auth.IsInvalidParamsError(err))
}

func TestUserCreate_AnonymousReturnAuthorizationErrorWhenCreateWithRoleNotOpen(t *testing.T) {
	uV := &mocks.Validator{}
	uV.On("Validate", mock.AnythingOfType("string")).Return(nil)

	pV := &mocks.Validator{}
	pV.On("Validate", mock.AnythingOfType("string")).Return(nil)

	rcs := []auth.RoleConfig{
		{
			Name: "test",
			Open: false,
		},
	}

	usecase := auth.UserCreate{
		UsernameValidator: uV,
		PasswordValidator: pV,
		RoleConfigs:       rcs,
	}

	u := createUserObject()
	_, err := usecase.Execute(u, "password", "")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserCreate_AuthorizationErrorWhenAuthUserCannotCreateRoleInNewUser(t *testing.T) {
	uV := &mocks.Validator{}
	uV.On("Validate", mock.AnythingOfType("string")).Return(nil)

	pV := &mocks.Validator{}
	pV.On("Validate", mock.AnythingOfType("string")).Return(nil)

	roleSlug := "test"
	rcs := []auth.RoleConfig{
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

	tR := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      authToken,
		UserID:     userID,
		Expiration: time.Now().Add(time.Hour),
	}
	tR.On("Get", authToken).Return(tok, nil)

	tV := auth.TokenAuthenticate{
		TokenRepo: tR,
	}

	uR := &mocks.UserRepo{}
	user := auth.User{
		UUID:     userID,
		Email:    "test@test.com",
		Username: "test",
		Roles:    []string{roleSlug},
	}
	uR.On("Get", userID).Return(user, nil)

	usecase := auth.UserCreate{
		UsernameValidator: uV,
		PasswordValidator: pV,
		RoleConfigs:       rcs,
		TokenAuthenticate: tV,
		UserRepo:          uR,
	}

	u := createUserObject()
	u.Roles = append(u.Roles, "test")
	_, err := usecase.Execute(u, "password", authToken)
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}
