package token_test

import (
	"errors"
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/calebmcelroy/tradelead-auth/token"
	"github.com/calebmcelroy/tradelead-auth/token/mocks"
	"github.com/calebmcelroy/tradelead-auth/user"
	usermocks "github.com/calebmcelroy/tradelead-auth/user/mocks"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestInvalidParamsErrorWhenMissingUsernamePassword(t *testing.T) {

	usecase := token.Create{}
	_, err := usecase.Execute("", "", false)
	assert.Equal(t, true, errs.IsInvalidParamsError(err))

}

func TestInsertsToken(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	usecase.Execute("test", "test", false)

	tokenRepo.AssertNumberOfCalls(t, "Insert", 1)
}

func TestAuthenticationErrorWhenInvalidCreds(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("", errs.NewAuthenticationError("Invalid credentials"))

	_, err := usecase.Execute("test", "test", false)

	tokenRepo.AssertNumberOfCalls(t, "Insert", 0)

	assert.Equal(t, true, errs.IsAuthenticationError(err))
}

func TestReturnsWrappedErrorWhenTokenRepoInsertError(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(errors.New("could not connect to db"))

	_, err := usecase.Execute("test", "test", false)

	assert.EqualError(t, err, "insert token failed: could not connect to db")
}

func TestEmptyTokenWhenTokenRepoError(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(errors.New("could not connect to db"))

	tok, _ := usecase.Execute("test", "test", false)

	assert.Equal(t, token.Token{}, tok)
}

func TestForCorrectUser(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, err := usecase.Execute("test", "test", false)

	assert.Nil(t, err)
	assert.Equal(t, "123", tk.UserID)
}

func TestForToken(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, err := usecase.Execute("test", "test", false)

	assert.Nil(t, err)
	assert.NotEmpty(t, tk.Token)
}

func TestFor1DayExp(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, _ := usecase.Execute("test", "test", false)

	expected := time.Now().Add(time.Hour * 24)
	assert.Equal(t, expected.Unix(), tk.Expiration.Unix())
}

func TestFor30DayExpOnRemember(t *testing.T) {
	userRepo := &usermocks.UserRepo{}

	verifyUser := user.VerifyCreds{
		UserRepo: userRepo,
	}

	tokenRepo := &mocks.TokenRepo{}

	usecase := token.Create{
		VerifyUserCreds: verifyUser,
		TokenRepo:       tokenRepo,
	}

	userRepo.On("Authenticate", "test", "test").Return("123", nil)
	tokenRepo.On("Insert", mock.Anything).Return(nil)

	tk, _ := usecase.Execute("test", "test", true)

	expected := time.Now().Add(time.Hour * 24 * 30)
	assert.Equal(t, expected.Unix(), tk.Expiration.Unix())
}
