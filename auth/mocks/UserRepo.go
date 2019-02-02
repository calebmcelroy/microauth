// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import auth "github.com/calebmcelroy/microauth/auth"
import mock "github.com/stretchr/testify/mock"

// UserRepo is an autogenerated mock type for the UserRepo type
type UserRepo struct {
	mock.Mock
}

// Get provides a mock function with given fields: userID
func (_m *UserRepo) Get(userID string) (auth.User, error) {
	ret := _m.Called(userID)

	var r0 auth.User
	if rf, ok := ret.Get(0).(func(string) auth.User); ok {
		r0 = rf(userID)
	} else {
		r0 = ret.Get(0).(auth.User)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByUsername provides a mock function with given fields: username
func (_m *UserRepo) GetByUsername(username string) (auth.User, error) {
	ret := _m.Called(username)

	var r0 auth.User
	if rf, ok := ret.Get(0).(func(string) auth.User); ok {
		r0 = rf(username)
	} else {
		r0 = ret.Get(0).(auth.User)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}