package auth_test

import (
	"github.com/calebmcelroy/microauth/auth"
	"github.com/calebmcelroy/microauth/auth/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGrantDelete_ReturnsErrorFromGrantRepo(t *testing.T) {
	grantRepo := &mocks.GrantRepo{}

	grantRepo.On("Delete", "uuid").Return(errors.New("test error"))

	usecase := auth.GrantDelete{GrantRepo: grantRepo}

	err := usecase.Execute("uuid")

	assert.EqualError(t, errors.Cause(err), "test error")
}
