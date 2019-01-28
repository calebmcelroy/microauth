// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"
import token "github.com/calebmcelroy/tradelead-auth/token"

// TokenRepo is an autogenerated mock type for the TokenRepo type
type TokenRepo struct {
	mock.Mock
}

// Delete provides a mock function with given fields: _a0
func (_m *TokenRepo) Delete(_a0 string) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: _a0
func (_m *TokenRepo) Get(_a0 string) (token.Token, error) {
	ret := _m.Called(_a0)

	var r0 token.Token
	if rf, ok := ret.Get(0).(func(string) token.Token); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(token.Token)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByUser provides a mock function with given fields: userID
func (_m *TokenRepo) GetByUser(userID string) ([]token.Token, error) {
	ret := _m.Called(userID)

	var r0 []token.Token
	if rf, ok := ret.Get(0).(func(string) []token.Token); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]token.Token)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Insert provides a mock function with given fields: _a0
func (_m *TokenRepo) Insert(_a0 token.Token) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(token.Token) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
