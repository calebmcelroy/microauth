package usecase

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/calebmcelroy/tradelead-auth/core/boundary/mocks"
	"github.com/calebmcelroy/tradelead-auth/core/entity"
)

func TestTrueIfExistsAndNotExpired(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := VerifyAuthToken{
		TokenRepo: tr,
	}

	token := entity.Token{
		Token:      "123456789",
		UserID:     "123",
		Expiration: time.Now().Add(time.Hour),
	}
	tr.On("Get", "123456789").Return(token, nil)

	userID, err := usecase.Execute("123456789")

	assert.Nil(t, err)
	assert.Equal(t, "123", userID)
}

func TestFalseIfExpired(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := VerifyAuthToken{
		TokenRepo: tr,
	}

	token := entity.Token{
		Token:      "123456789",
		UserID:     "123",
		Expiration: time.Now().Add(-time.Hour),
	}
	tr.On("Get", "123456789").Return(token, nil)

	userID, err := usecase.Execute("123456789")

	assert.Equal(t, "", userID)
	assert.Equal(t, true, IsAuthenticationError(err))
}

func TestFalseWhenNotFound(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := VerifyAuthToken{
		TokenRepo: tr,
	}

	token := entity.Token{}
	tr.On("Get", "123456789").Return(token, nil)

	userID, err := usecase.Execute("123456789")

	assert.Equal(t, "", userID)
	assert.Equal(t, true, IsAuthenticationError(err))
}

func TestReturnsWrapErrorFromTokenRepo(t *testing.T) {
	tr := &mocks.TokenRepo{}

	usecase := VerifyAuthToken{
		TokenRepo: tr,
	}

	returnedErr := errors.New("test error")
	tr.On("Get", "123456789").Return(entity.Token{}, returnedErr)

	_, err := usecase.Execute("123456789")

	assert.Equal(t, err.Error(), "failed getting token: test error")
}
