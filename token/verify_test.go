package token_test

import (
	"errors"
	"github.com/calebmcelroy/tradelead-auth/errs"
	"github.com/calebmcelroy/tradelead-auth/token"
	"github.com/calebmcelroy/tradelead-auth/token/mocks"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTrueIfExistsAndNotExpired(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := token.Verify{
		TokenRepo: tr,
	}

	tk := token.Token{
		Token:      "123456789",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", "123456789").Return(tk, nil)

	userID, err := usecase.Execute("123456789")

	assert.Nil(t, err)
	assert.Equal(t, "123", userID)
}

func TestFalseIfExpired(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := token.Verify{
		TokenRepo: tr,
	}

	tk := token.Token{
		Token:      "123456789",
		UserID:     "123",
		Expiration: time.Now().Add(-time.Hour),
	}
	tr.On("Get", "123456789").Return(tk, nil)

	userID, err := usecase.Execute("123456789")

	assert.Equal(t, "", userID)
	assert.Equal(t, true, errs.IsAuthenticationError(err))
}

func TestFalseWhenNotFound(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := token.Verify{
		TokenRepo: tr,
	}

	tk := token.Token{}
	tr.On("Get", "123456789").Return(tk, nil)

	userID, err := usecase.Execute("123456789")

	assert.Equal(t, "", userID)
	assert.Equal(t, true, errs.IsAuthenticationError(err))
}

func TestReturnsWrapErrorFromTokenRepo(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := token.Verify{
		TokenRepo: tr,
	}

	returnedErr := errors.New("test error")
	tr.On("Get", "123456789").Return(token.Token{}, returnedErr)

	_, err := usecase.Execute("123456789")

	assert.Equal(t, err.Error(), "failed getting token: test error")
}
