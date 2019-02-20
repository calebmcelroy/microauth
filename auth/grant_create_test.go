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

func TestGrantCreate_InvalidConfigurationReturnsError(t *testing.T) {
	c := auth.GrantConfig{}
	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.EqualError(t, err, "invalid grant configuration")
}

func TestGrantCreate_ReturnsErrorWhenTypeMissing(t *testing.T) {
	c := auth.GrantConfig{}
	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
	}

	r := auth.GrantCreateRequest{
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestGrantCreate_ReturnsErrorWhenUserUUIDMissing(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestGrantCreate_ReturnsErrorWhenAuthTokenMissing(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
	}

	r := auth.GrantCreateRequest{
		Type:     "test",
		UserUUID: "userUUID",
		Password: "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestGrantCreate_ReturnsUserRepoGetUserError(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{}, errors.New("test error"))

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestGrantCreate_ReturnsTokAuthError(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID",
		Expiration: time.Now().Add(-time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsAuthenticationError(errors.Cause(err)))
}

func TestGrantCreate_ReturnsUserRepoGetAuthUserError(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	u.On("Get", "userUUID2").Return(auth.User{}, errors.New("test error"))

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestGrantCreate_AuthenticationErrorWhenAuthUserDoesntExist(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	u.On("Get", "userUUID2").Return(auth.User{}, nil)

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsAuthenticationError(errors.Cause(err)))
}

func TestGrantCreate_CantCreateGrantReturnsAuthorizationError(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return false
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	u.On("Get", "userUUID2").Return(auth.User{
		UUID: "userUUID2",
	}, nil)

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantCreate_ReturnsGrantRepoErrorOnCreate(t *testing.T) {
	c := auth.GrantConfig{
		Slug: "test",
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	u.On("Get", "userUUID2").Return(auth.User{
		UUID: "userUUID2",
	}, nil)

	grantRepo := &mocks.GrantRepo{}
	grantRepo.On("Create", mock.Anything).Return(errors.New("test error"))

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		GrantRepo:    grantRepo,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestGrantCreate_SuccessCreatedNonSecureGrant(t *testing.T) {
	c := auth.GrantConfig{
		Slug:     "test",
		Duration: time.Hour,
		Secure:   false,
		Limit:    5,
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	u.On("Get", "userUUID2").Return(auth.User{
		UUID:     "userUUID2",
		Username: "test",
		Email:    "test@test.com",
	}, nil)

	grantRepo := &mocks.GrantRepo{}
	grantRepo.On("Create", mock.Anything).Return(nil)

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		GrantRepo:    grantRepo,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Nil(t, err)
}

func TestGrantCreate_SecureGrantReturnBadRequestErrorWhenMissingPassword(t *testing.T) {
	c := auth.GrantConfig{
		Slug:     "test",
		Duration: time.Hour,
		Secure:   true,
		Limit:    5,
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	authUser := auth.User{
		UUID:         "userUUID2",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "passHash",
	}

	u.On("Get", "userUUID2").Return(authUser, nil)
	u.On("GetByUsername", "test").Return(authUser, nil)

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "password").Return("passHash")

	userAuth := auth.UserAuthenticate{
		UserRepo:       u,
		PasswordHasher: passHasher,
	}

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		UserAuth:     userAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsBadRequestError(errors.Cause(err)))
}

func TestGrantCreate_SecureGrantReturnUserAuthError(t *testing.T) {
	c := auth.GrantConfig{
		Slug:     "test",
		Duration: time.Hour,
		Secure:   true,
		Limit:    5,
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	authUser := auth.User{
		UUID:         "userUUID2",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "passHash",
	}

	u.On("Get", "userUUID2").Return(authUser, nil)
	u.On("GetByUsername", "test").Return(authUser, nil)

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "password").Return("passHash2")

	userAuth := auth.UserAuthenticate{
		UserRepo:       u,
		PasswordHasher: passHasher,
	}

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		UserAuth:     userAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsAuthenticationError(errors.Cause(err)))
}

func TestGrantCreate_SecureGrantErrorWhenAuthUserDoesntMatchAuthTokenUser(t *testing.T) {
	c := auth.GrantConfig{
		Slug:     "test",
		Duration: time.Hour,
		Secure:   true,
		Limit:    5,
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	authUser := auth.User{
		UUID:         "userUUID2",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "passHash",
	}

	u.On("Get", "userUUID2").Return(authUser, nil)
	u.On("GetByUsername", "test").Return(auth.User{}, nil)

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "password").Return("passHash")

	userAuth := auth.UserAuthenticate{
		UserRepo:       u,
		PasswordHasher: passHasher,
	}

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		UserAuth:     userAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Equal(t, true, auth.IsAuthenticationError(errors.Cause(err)))
}

func TestGrantCreate_VerifyCreatedGrant(t *testing.T) {
	c := auth.GrantConfig{
		Slug:     "test",
		Duration: time.Hour,
		Secure:   true,
		Limit:    5,
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	authUser := auth.User{
		UUID:         "userUUID2",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "passHash",
	}

	u.On("Get", "userUUID2").Return(authUser, nil)
	u.On("GetByUsername", "test").Return(authUser, nil)

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "password").Return("passHash")

	userAuth := auth.UserAuthenticate{
		UserRepo:       u,
		PasswordHasher: passHasher,
	}

	grantRepo := &mocks.GrantRepo{}
	grantRepo.On("Create", mock.MatchedBy(func(g auth.Grant) bool {
		assert.Equal(t, true, g.UserID == "userUUID")
		assert.Equal(t, true, g.TypeSlug == "test")
		assert.Equal(t, true, g.Expires.Unix() == time.Now().Add(c.Duration).Unix())
		assert.Equal(t, true, g.Secure == true)
		assert.Equal(t, true, g.UseLimit == 5)
		return true
	})).Return(nil)

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		GrantRepo:    grantRepo,
		UserAuth:     userAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Nil(t, err)
}

func TestGrantCreate_VerifyCreatedGrantWithoutExpiration(t *testing.T) {
	c := auth.GrantConfig{
		Slug:     "test",
		Duration: 0,
		Secure:   true,
		Limit:    5,
		CanCreateGrant: func(g auth.Grant, u auth.User, authUser auth.User) bool {
			return true
		},
	}

	u := &mocks.UserRepo{}
	u.On("Get", "userUUID").Return(auth.User{
		UUID: "userUUID",
	}, nil)

	tokRepo := &mocks.TokenRepo{}

	tok := auth.Token{
		Token:      "authToken",
		UserID:     "userUUID2",
		Expiration: time.Now().Add(time.Hour),
	}

	tokRepo.On("Get", "authToken").Return(tok, nil)

	tokAuth := auth.TokenAuthenticate{
		TokenRepo: tokRepo,
	}

	authUser := auth.User{
		UUID:         "userUUID2",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "passHash",
	}

	u.On("Get", "userUUID2").Return(authUser, nil)
	u.On("GetByUsername", "test").Return(authUser, nil)

	passHasher := &mocks.Hasher{}
	passHasher.On("Hash", "password").Return("passHash")

	userAuth := auth.UserAuthenticate{
		UserRepo:       u,
		PasswordHasher: passHasher,
	}

	grantRepo := &mocks.GrantRepo{}
	grantRepo.On("Create", mock.MatchedBy(func(g auth.Grant) bool {
		assert.Equal(t, true, g.Expires.IsZero())
		return true
	})).Return(nil)

	usecase := auth.GrantCreate{
		GrantConfigs: []auth.GrantConfig{c},
		UserRepo:     u,
		TokAuth:      tokAuth,
		GrantRepo:    grantRepo,
		UserAuth:     userAuth,
	}

	r := auth.GrantCreateRequest{
		Type:      "test",
		UserUUID:  "userUUID",
		AuthToken: "authToken",
		Password:  "password",
	}

	err := usecase.Execute(r)

	assert.Nil(t, err)
}
