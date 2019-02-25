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

func TestUserGenerateTOTPToken_BadRequestWhenMissingUserUUID(t *testing.T) {
	usecase := auth.UserGenerateTOTPToken{}
	_, err := usecase.Execute("", "authToken")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserGenerateTOTPToken_BadRequestWhenMissingAuthToken(t *testing.T) {
	usecase := auth.UserGenerateTOTPToken{}
	_, err := usecase.Execute("userUUID", "")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserGenerateTOTPToken_AuthenticationErrorWhenInvalidAuthToken(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tokRepo.On("Get", "authToken").Return(auth.Token{}, nil)

	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}
	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestUserGenerateTOTPToken_ReturnErrorFromUserRepoGet(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	userRepo.On("Get", "userUUID").Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserGenerateTOTPToken_ReturnErrorFromUserRepoGetAuthUser(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	userRepo.On("Get", "userUUID").Return(auth.User{}, nil)
	userRepo.On("Get", "userUUID2").Return(auth.User{}, errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserGenerateTOTPToken_AuthorizationErrorWhenCanEditUserAllFalse(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:  "userUUID",
		Roles: []string{"test"},
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestUserGenerateTOTPToken_ReturnErrorFromUserOTPRepoIsActivated(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:  "userUUID",
		Roles: []string{"test"},
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
		UserOTPRepo:       otpRepo,
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserGenerateTOTPToken_BadRequestWhenAlreadyActivated(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:  "userUUID",
		Roles: []string{"test"},
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(true, nil)

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
		UserOTPRepo:       otpRepo,
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestUserGenerateTOTPToken_ReturnErrorFromTOTPGenerateKey(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	totp.On("GenerateKey", "Test Org", "test@test.com").Return("", errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
		UserOTPRepo:       otpRepo,
		TOTP:              totp,
		Issuer:            "Test Org",
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserGenerateTOTPToken_ReturnErrorFromUserOTPRepoSave(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	optURL := "otpauth://totp/Test%20Org:test@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Test%20Org&algorithm=SHA1&digits=6&period=30"
	totp.On("GenerateKey", "Test Org", "test@test.com").Return(optURL, nil)

	otpRepo.On("Save", "userUUID", optURL).Return(errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate: tokAuth,
		UserRepo:          userRepo,
		RoleConfigs:       roleConfigs,
		UserOTPRepo:       otpRepo,
		TOTP:              totp,
		Issuer:            "Test Org",
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserGenerateTOTPToken_ReturnErrorFromUserRecoveryCodeRepoSet(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	optURL := "otpauth://totp/Test%20Org:test@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Test%20Org&algorithm=SHA1&digits=6&period=30"
	totp.On("GenerateKey", "Test Org", "test@test.com").Return(optURL, nil)

	otpRepo.On("Save", "userUUID", optURL).Return(nil)

	recoveryCodeRepo := &mocks.UserRecoveryCodeRepo{}
	recoveryCodeRepo.On("Set", mock.Anything, "userUUID").Return(errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate:    tokAuth,
		UserRepo:             userRepo,
		RoleConfigs:          roleConfigs,
		UserOTPRepo:          otpRepo,
		TOTP:                 totp,
		UserRecoveryCodeRepo: recoveryCodeRepo,
		Issuer:               "Test Org",
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestUserGenerateTOTPToken_SaveValidRecoveryCodes(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	optURL := "otpauth://totp/Test%20Org:test@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Test%20Org&algorithm=SHA1&digits=6&period=30"
	totp.On("GenerateKey", "Test Org", "test@test.com").Return(optURL, nil)

	otpRepo.On("Save", "userUUID", optURL).Return(nil)

	recoveryCodeRepo := &mocks.UserRecoveryCodeRepo{}
	recoveryCodeRepo.On("Set", mock.MatchedBy(func(codes []string) bool {
		assert.NotEmpty(t, codes)
		for _, code := range codes {
			assert.NotEmpty(t, code)
		}
		return true
	}), "userUUID").Return(errors.New("test error"))

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate:    tokAuth,
		UserRepo:             userRepo,
		RoleConfigs:          roleConfigs,
		UserOTPRepo:          otpRepo,
		TOTP:                 totp,
		UserRecoveryCodeRepo: recoveryCodeRepo,
		Issuer:               "Test Org",
	}
	usecase.Execute("userUUID", "authToken")
}

func TestUserGenerateTOTPToken_ReturnsValidRecoveryCodes(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	optURL := "otpauth://totp/Test%20Org:test@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Test%20Org&algorithm=SHA1&digits=6&period=30"
	totp.On("GenerateKey", "Test Org", "test@test.com").Return(optURL, nil)

	otpRepo.On("Save", "userUUID", optURL).Return(nil)

	recoveryCodeRepo := &mocks.UserRecoveryCodeRepo{}
	recoveryCodeRepo.On("Set", mock.Anything, "userUUID").Return(nil)

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate:    tokAuth,
		UserRepo:             userRepo,
		RoleConfigs:          roleConfigs,
		UserOTPRepo:          otpRepo,
		TOTP:                 totp,
		UserRecoveryCodeRepo: recoveryCodeRepo,
		Issuer:               "Test Org",
	}
	res, _ := usecase.Execute("userUUID", "authToken")

	assert.NotEmpty(t, res.RecoveryCodes)
	for _, code := range res.RecoveryCodes {
		assert.NotEmpty(t, code)
	}
}

func TestUserGenerateTOTPToken_ReturnsCorrectOPTURL(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	authUser := auth.User{
		UUID:  "userUUID2",
		Roles: []string{"admin", "test"},
	}
	userRepo.On("Get", "userUUID2").Return(authUser, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
		{
			Name: "Admin",
			Slug: "admin",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return true
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	optURL := "otpauth://totp/Test%20Org:test@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Test%20Org&algorithm=SHA1&digits=6&period=30"
	totp.On("GenerateKey", "Test Org", "test@test.com").Return(optURL, nil)

	otpRepo.On("Save", "userUUID", optURL).Return(nil)

	recoveryCodeRepo := &mocks.UserRecoveryCodeRepo{}
	recoveryCodeRepo.On("Set", mock.Anything, "userUUID").Return(nil)

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate:    tokAuth,
		UserRepo:             userRepo,
		RoleConfigs:          roleConfigs,
		UserOTPRepo:          otpRepo,
		TOTP:                 totp,
		UserRecoveryCodeRepo: recoveryCodeRepo,
		Issuer:               "Test Org",
	}
	res, _ := usecase.Execute("userUUID", "authToken")

	assert.Equal(t, auth.OTPURL(optURL), res.OTPURL)
}

func TestUserGenerateTOTPToken_AuthorizedWhenAuthUserMatchUserUUID(t *testing.T) {
	tokRepo := &mocks.TokenRepo{}
	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID",
		Expiration: time.Now().Add(time.Hour),
	}
	tokRepo.On("Get", "authToken").Return(tok, nil)
	tokAuth := auth.TokenAuthenticate{TokenRepo: tokRepo}

	userRepo := &mocks.UserRepo{}
	user := auth.User{
		UUID:     "userUUID",
		Roles:    []string{"test"},
		Username: "test@test.com",
	}
	userRepo.On("Get", "userUUID").Return(user, nil)

	roleConfigs := []auth.RoleConfig{
		{
			Name: "Test",
			Slug: "test",
			Open: false,
			CanEditUser: func(editUser auth.User, u auth.User) bool {
				return false
			},
		},
	}

	otpRepo := &mocks.UserOTPRepo{}
	otpRepo.On("IsActivated", "userUUID").Return(false, nil)

	totp := &mocks.TOTP{}
	optURL := "otpauth://totp/Test%20Org:test@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Test%20Org&algorithm=SHA1&digits=6&period=30"
	totp.On("GenerateKey", "Test Org", "test@test.com").Return(optURL, nil)

	otpRepo.On("Save", "userUUID", optURL).Return(nil)

	recoveryCodeRepo := &mocks.UserRecoveryCodeRepo{}
	recoveryCodeRepo.On("Set", mock.Anything, "userUUID").Return(nil)

	usecase := auth.UserGenerateTOTPToken{
		TokenAuthenticate:    tokAuth,
		UserRepo:             userRepo,
		RoleConfigs:          roleConfigs,
		UserOTPRepo:          otpRepo,
		TOTP:                 totp,
		UserRecoveryCodeRepo: recoveryCodeRepo,
		Issuer:               "Test Org",
	}
	_, err := usecase.Execute("userUUID", "authToken")
	assert.Nil(t, err)
}
