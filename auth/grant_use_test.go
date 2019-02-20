package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGrantUse_BadRequestErrorWhenMissingGrant(t *testing.T) {
	usecase := auth.GrantUse{}

	err := usecase.Execute("")

	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestGrantUse_ReturnErrorFromGrantRepoGet(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{}

	grantRepo.On("Get", "uuid").Return(g, errors.New("test error"))

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestGrantUse_AuthorizationErrorWhenGrantDoesntExist(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{}

	grantRepo.On("Get", "uuid").Return(g, nil)

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantUse_AuthorizationErrorWhenGrantUsedUp(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Now().Add(-time.Hour),
		Secure:   true,
		Uses:     4,
		UseLimit: 4,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantUse_AuthorizationErrorWhenGrantExpired(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantUse_NotAuthorizationErrorWhenGrantExpirationTimeIsZero(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Time{},
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
		Version:  1,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)
	grantRepo.On("Use", "uuid", 1).Return(nil)

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	assert.Equal(t, false, auth.IsAuthorizationError(err))
}

func TestGrantUse_ReturnErrorFromGrantRepoUse(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Now().Add(-time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
		Version:  1,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)
	grantRepo.On("Use", "uuid", 1).Return(errors.New("test error"))

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")
	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestGrantUse_NilOnSuccessAndCallsGrantRepoUse(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Now().Add(-time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
		Version:  1,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)
	grantRepo.On("Use", "uuid", 1).Return(nil)

	usecase := auth.GrantUse{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	grantRepo.AssertCalled(t, "Use", "uuid", 1)
	assert.Nil(t, err)
}
