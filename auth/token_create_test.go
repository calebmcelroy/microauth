package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log"
	"testing"
	"time"
)

func TestTokenCreate_BadRequestErrorWhenMissingUsernamePassword(t *testing.T) {

	usecase := auth.TokenCreate{}
	_, err := usecase.Execute("", "", false)
	assert.Equal(t, true, auth.IsBadRequestError(err))

}

func TestTokenCreate_InsertsToken(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}
	hasher.On("Hash", "test").Return("test")

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tok, err := usecase.Execute("test", "test", false)
	log.Println(tok, err)

	tokenRepo.AssertNumberOfCalls(t, "Insert", 1)
}

func TestTokenCreate_AuthenticationErrorWhenInvalidCreds(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	hasher.On("Hash", "test").Return("test")
	userRepo.On("GetByUsername", "test").Return(auth.User{}, nil)

	_, err := usecase.Execute("test", "test", false)

	tokenRepo.AssertNumberOfCalls(t, "Insert", 0)

	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestTokenCreate_ReturnsWrappedErrorWhenTokenRepoInsertError(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	tokenRepo.On("Insert", mock.Anything).Return(errors.New("could not connect to db"))

	_, err := usecase.Execute("test", "test", false)

	assert.EqualError(t, err, "insert auth failed: could not connect to db")
}

func TestTokenCreate_EmptyTokenWhenTokenRepoError(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	tokenRepo.On("Insert", mock.Anything).Return(errors.New("could not connect to db"))

	tok, _ := usecase.Execute("test", "test", false)

	assert.Equal(t, auth.Token{}, tok)
}

func TestTokenCreate_ForCorrectUser(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, err := usecase.Execute("test", "test", false)

	assert.Nil(t, err)
	assert.Equal(t, "123", tk.UserID)
}

func TestTokenCreate_ForToken(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, err := usecase.Execute("test", "test", false)

	assert.Nil(t, err)
	assert.NotEmpty(t, tk.Token)
}

func TestTokenCreate_For1DayExp(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, _ := usecase.Execute("test", "test", false)

	expected := time.Now().Add(time.Hour * 24)
	assert.Equal(t, expected.Unix(), tk.Expiration.Unix())
}

func TestTokenCreate_For30DayExpOnRemember(t *testing.T) {
	userRepo := &mocks.UserRepo{}
	hasher := &mocks.Hasher{}

	verifyUser := auth.UserAuthenticate{
		UserRepo:       userRepo,
		PasswordHasher: hasher,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := auth.TokenCreate{
		UserAuthenticate: verifyUser,
		TokenRepo:        tokenRepo,
	}

	user := auth.User{
		UUID:         "123",
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "test",
	}
	userRepo.On("GetByUsername", "test").Return(user, nil)
	hasher.On("Hash", "test").Return("test")
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, _ := usecase.Execute("test", "test", true)

	expected := time.Now().Add(time.Hour * 24 * 30)
	assert.Equal(t, expected.Unix(), tk.Expiration.Unix())
}
