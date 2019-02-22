package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGrantInfo_BadRequestErrorWhenMissingUUID(t *testing.T) {
	usecase := auth.GrantInfo{}

	_, err := usecase.Execute("")

	assert.Equal(t, true, auth.IsBadRequestError(err))
}

func TestGrantInfo_ReturnErrorFromGrantRepoGet(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{}

	grantRepo.On("Get", "uuid").Return(g, errors.New("test error"))

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	_, err := usecase.Execute("uuid")

	assert.EqualError(t, errors.Cause(err), "test error")
}

func TestGrantInfo_NotFoundErrorWhenGrantDoesntExist(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{}

	grantRepo.On("Get", "uuid").Return(g, nil)

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	_, err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsNotFoundError(err))
}

func TestGrantInfo_AuthorizationErrorWhenGrantUsedUp(t *testing.T) {
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

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	_, err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantInfo_AuthorizationErrorWhenGrantExpired(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Now().Add(-time.Hour),
		Secure:   true,
		Uses:     3,
		UseLimit: 4,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	_, err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantInfo_AuthorizationErrorWhenGrantUsed(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	g := auth.Grant{
		UUID:     "uuid",
		UserID:   "userUUID",
		TypeSlug: "test",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		Uses:     4,
		UseLimit: 4,
	}

	grantRepo.On("Get", "uuid").Return(g, nil)

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	_, err := usecase.Execute("uuid")

	assert.Equal(t, true, auth.IsAuthorizationError(err))
}

func TestGrantInfo_NotAuthorizationErrorWhenGrantExpirationTimeIsZero(t *testing.T) {
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

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	_, err := usecase.Execute("uuid")

	assert.Equal(t, false, auth.IsAuthorizationError(err))
}

func TestGrantInfo_ReturnGrantOnSuccess(t *testing.T) {
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

	usecase := auth.GrantInfo{GrantRepo: grantRepo}

	resGrant, err := usecase.Execute("uuid")

	assert.Nil(t, err)
	assert.Equal(t, g.UUID, resGrant.UUID)
	assert.Equal(t, g.UserID, resGrant.UserID)
	assert.Equal(t, g.TypeSlug, resGrant.TypeSlug)
	assert.Equal(t, g.Expires, resGrant.Expires)
	assert.Equal(t, g.Secure, resGrant.Secure)
	assert.Equal(t, g.Uses, resGrant.Uses)
	assert.Equal(t, g.UseLimit, resGrant.UseLimit)
	assert.Equal(t, g.Version, resGrant.Version)
}
