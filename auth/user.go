package auth

import (
	"github.com/pkg/errors"
	"regexp"
)

//User is the entity for passing user
type User struct {
	UUID         string
	Email        string
	Username     string
	Roles        []string
	PasswordHash string
}

// UserRepo is used for storage and retrieval of user data.
type UserRepo interface {
	// Authenticate verifies user credentials and retrieve user identifier
	// returns err that implements Authorization() if username or password is invalid
	Get(userID string) (user User, err error)
	GetByUsername(username string) (user User, err error)
}

// Hasher simple interface for Hash method
type Hasher interface {
	//Hash a string
	Hash(string) string
}

// RoleConfig is used to define a role, including it's name, slug, & capabilities
type RoleConfig struct {
	// Name is for displaying purposes
	Name string

	// Slug is used as the identifier for a role and must be unique
	Slug string

	// Open defines whether anyone can register without authentication or authorization
	Open bool

	// CanCreateUser is used to validate whether an authenticated user
	// is allowed to create a new user with this role
	CanCreateUser func(newUser User, u User) bool

	// CanAssignUserRole is used to validate whether an authenticated user
	// is allowed to assign this role to a particular user
	CanAssignUserRole func(targetUser User, u User) bool

	// CanRemoveUserRole is used to validate whether an authenticated user
	// is allowed to remove this role from a particular user
	CanRemoveUserRole func(targetUser User, u User) bool

	// CanGetOtherUserInfo is used to validate whether an authenticated user
	// is allowed to GetInfo from another user with this role
	// if the user has multiple roles this func is ran for each role
	// checking if any returns true
	CanGetOtherUserInfo func(targetUser User, u User) bool
}

type UserCreate struct {
	UsernameValidator Validator
	PasswordValidator Validator
	RoleConfigs       []RoleConfig
	TokenAuthenticate TokenAuthenticate
	UserRepo          UserRepo
	PasswordHasher    Hasher
}

func (u UserCreate) Execute(user User, password string, authToken string) (ID string, error error) {

	invalidParams := user.Username == "" ||
		user.Email == "" ||
		password == "" ||
		len(user.Roles) == 0

	if invalidParams {
		return "", newInvalidParamsError("username, email, password, and role are required")
	}

	rxEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if !rxEmail.MatchString(user.Email) {
		return "", newInvalidParamsError("email invalid")
	}

	err := u.UsernameValidator.Validate(user.Username)
	if err != nil {
		return "", newInvalidParamsError(err.Error())
	}

	err = u.PasswordValidator.Validate(password)
	if err != nil {
		return "", newInvalidParamsError(err.Error())
	}

	if authToken != "" {
		authUserID, err := u.TokenAuthenticate.Execute(authToken)
		if err != nil {
			return "", err
		}

		authUser, err := u.UserRepo.Get(authUserID)
		if err != nil {
			return "", err
		}

		if !canAuthUserCreateUser(u.RoleConfigs, user, authUser) {
			return "", newAuthorizationError("cannot create user with role")
		}
	} else {
		for _, r := range user.Roles {
			rc := getRoleConfig(u.RoleConfigs, r)
			if !rc.Open {
				return "", newAuthorizationError("cannot create user with role '" + r + "'")
			}

			if authToken != "" {

			}
		}
	}

	return "", nil
}

func canAuthUserCreateUser(rcs []RoleConfig, newUser User, authUser User) bool {
	if len(rcs) == 0 {
		return false
	}

	for _, r := range rcs {
		if !r.CanCreateUser(newUser, authUser) {
			return false
		}
	}

	return true
}

func getRoleConfig(rcs []RoleConfig, role string) RoleConfig {
	for _, r := range rcs {
		if r.Slug == role {
			return r
		}
	}

	return RoleConfig{}
}

//UserAuthenticate is used to validate a user's credentials
type UserAuthenticate struct {
	UserRepo       UserRepo
	PasswordHasher Hasher
}

//Execute returns userID on success and empty userID if invalid.
func (a UserAuthenticate) Execute(username string, password string) (userID string, error error) {
	if username == "" || password == "" {
		return "", newInvalidParamsError("username and password are required")
	}

	u, err := a.UserRepo.GetByUsername(username)

	if err != nil {
		return "", errors.Wrap(err, "failed getting user")
	}

	passMatch := u.PasswordHash == a.PasswordHasher.Hash(password)

	if u.PasswordHash == "" || !passMatch {
		return "", newAuthenticationError("invalid username or password")
	}

	return u.UUID, nil
}
