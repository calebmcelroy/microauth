package errs

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCustomError_Error(t *testing.T) {
	e := customError{errors.New("test error")}
	assert.EqualError(t, e, "test error")
}
