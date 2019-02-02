package auth_test

import (
	"errors"
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenVerify_TrueIfExistsAndNotExpired(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := auth.TokenAuthenticate{
		TokenRepo: tr,
	}

	tk := auth.Token{
		Token:      "123456789",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", "123456789").Return(tk, nil)

	userID, err := usecase.Execute("123456789")

	assert.Nil(t, err)
	assert.Equal(t, "123", userID)
}

func TestTokenVerify_FalseIfExpired(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := auth.TokenAuthenticate{
		TokenRepo: tr,
	}

	tk := auth.Token{
		Token:      "123456789",
		UserID:     "123",
		Expiration: time.Now().Add(-time.Hour),
	}
	tr.On("Get", "123456789").Return(tk, nil)

	userID, err := usecase.Execute("123456789")

	assert.Equal(t, "", userID)
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestTokenVerify_FalseWhenNotFound(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := auth.TokenAuthenticate{
		TokenRepo: tr,
	}

	tk := auth.Token{}
	tr.On("Get", "123456789").Return(tk, nil)

	userID, err := usecase.Execute("123456789")

	assert.Equal(t, "", userID)
	assert.Equal(t, true, auth.IsAuthenticationError(err))
}

func TestTokenVerify_ReturnsWrapErrorFromTokenRepo(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := auth.TokenAuthenticate{
		TokenRepo: tr,
	}

	returnedErr := errors.New("test error")
	tr.On("Get", "123456789").Return(auth.Token{}, returnedErr)

	_, err := usecase.Execute("123456789")

	assert.Equal(t, err.Error(), "failed getting auth: test error")
}
