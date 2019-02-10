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

func TestUserInfo_BadRequestErrorWhenUsernameEmpty(t *testing.T) {
	usecase := auth.UserInfo{}
	_, err := usecase.Execute("", "123")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserInfo_BadRequestErrorWhenAuthTokenEmpty(t *testing.T) {
	usecase := auth.UserInfo{}
	_, err := usecase.Execute("123", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserInfo_AuthenticationErrorWhenAuthTokenInvalid(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", mock.Anything).Return(auth.Token{}, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
	}

	_, err := usecase.Execute("123", "authToken")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserInfo_ReturnErrorWhenTokenAuthenticateFailed(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", mock.Anything).Return(auth.Token{}, errors.New("test error"))
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
	}

	_, err := usecase.Execute("123", "authToken")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserInfo_AuthorizationErrorWhenUsernameNotFound(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	userRepo.On("Get", "123").Return(auth.User{}, nil)

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}

	_, err := usecase.Execute("123", "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserInfo_ReturnErrorWhenUserRepoGetByUsernameFails(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	userRepo.On("Get", "123").Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}

	_, err := usecase.Execute("123", "authToken")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserInfo_ReturnErrorWhenUserRepoFailedToGetAuthUser(t *testing.T) {
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

	userRepo.On("Get", "userID").Return(auth.User{}, errors.New("test error"))

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: roleSlug,
			Open: false,
			CanGetOtherUserInfo: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	_, err := usecase.Execute("123", "authToken")
	assert.Equal(t, "test error", errors.Cause(err).Error())
}

func TestUserInfo_AuthorizationErrorWhenUserRoleConfigUnauthorized(t *testing.T) {
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
			CanGetOtherUserInfo: func(newUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	_, err := usecase.Execute("123", "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserInfo_ReturnsUserMinusPassHashWhenUserRoleConfigAuthorized(t *testing.T) {
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
		UUID:         "123",
		PasswordHash: "passHash",
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
			CanGetOtherUserInfo: func(newUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	usecase := auth.UserInfo{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}

	userRes, err := usecase.Execute("123", "authToken")

	assert.Nil(t, err)

	user.PasswordHash = ""
	assert.Equal(t, user, userRes)
}
