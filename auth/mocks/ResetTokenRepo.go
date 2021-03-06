// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import auth "github.com/calebmcelroy/microauth/auth"
import mock "github.com/stretchr/testify/mock"

// ResetTokenRepo is an autogenerated mock type for the ResetTokenRepo type
type ResetTokenRepo struct {
	mock.Mock
}

// Delete provides a mock function with given fields: UUID
func (_m *ResetTokenRepo) Delete(UUID string) error {
	ret := _m.Called(UUID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(UUID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: UUID
func (_m *ResetTokenRepo) Get(UUID string) (auth.ResetToken, error) {
	ret := _m.Called(UUID)

	var r0 auth.ResetToken
	if rf, ok := ret.Get(0).(func(string) auth.ResetToken); ok {
		r0 = rf(UUID)
	} else {
		r0 = ret.Get(0).(auth.ResetToken)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(UUID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Insert provides a mock function with given fields: _a0
func (_m *ResetTokenRepo) Insert(_a0 auth.ResetToken) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(auth.ResetToken) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
