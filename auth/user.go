package auth

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"regexp"
	"time"
)

// User is the entity for passing user
type User struct {
	// UUID is unique and cannot be changed. UUID is generated by UserCreate
	UUID string

	// Email is unique and can be changed by user.
	Email string

	// Username is unique and can be changed by user.
	Username string

	// Roles is a unique slice of role slugs
	Roles []string

	PasswordHash string

	// Version is used for optimistic locking by UserRepo.Update(User).
	Version uint
}

// UserCreate creates a user.
type UserCreate struct {
	UsernameValidator Validator
	PasswordValidator Validator

	// RoleConfigs is used to verify authorization to create
	RoleConfigs       []RoleConfig
	TokenAuthenticate TokenAuthenticate
	UserRepo          UserRepo
	PasswordHasher    Hasher
}

// Execute params user.Username, user.Email, user.Roles, & password are required. user.UUID is generated.
// The authToken param is optional, although configuration within RoleConfigs may require authorization
// for the role being created. See RoleConfig.
// UsernameValidator & PasswordValidator validate if the username/password are conform to requirements.
func (u UserCreate) Execute(user User, password string, authToken string) (ID string, error error) {

	badRequest := user.Username == "" ||
		user.Email == "" ||
		password == "" ||
		len(user.Roles) == 0

	if badRequest {
		return "", newBadRequestError("username, email, password, and role are required")
	}

	if !validateEmail(user.Email) {
		return "", newBadRequestError("email invalid")
	}

	err := u.UsernameValidator.Validate(user.Username)
	if err != nil {
		return "", newBadRequestError(err.Error())
	}

	err = u.PasswordValidator.Validate(password)
	if err != nil {
		return "", newBadRequestError(err.Error())
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
		}
	}

	user.UUID = uuid.New().String()
	err = u.UserRepo.Insert(user)

	if err != nil {
		return "", errors.Wrap(err, "failed inserting user into db")
	}

	return user.UUID, nil
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

// UserAuthenticate validates a user's credentials
type UserAuthenticate struct {
	UserRepo       UserRepo
	PasswordHasher Hasher
}

// Execute returns nil error on success. An error implementing Authentication() is returned when invalid.
// An error implementing BadRequest() is return when username or password are empty.
func (a UserAuthenticate) Execute(usernameEmail string, password string) (userID string, error error) {
	if usernameEmail == "" || password == "" {
		return "", newBadRequestError("username/email and password are required")
	}

	var u User
	err := errors.New("")

	if validateEmail(usernameEmail) {
		u, err = a.UserRepo.GetByEmail(usernameEmail)
	} else {
		u, err = a.UserRepo.GetByUsername(usernameEmail)
	}

	if err != nil {
		return "", errors.Wrap(err, "failed getting user")
	}

	passMatch := u.PasswordHash == a.PasswordHasher.Hash(password)

	if u.PasswordHash == "" || !passMatch {
		return "", newAuthenticationError("invalid username/email or password")
	}

	return u.UUID, nil
}

// UsernameExists checks if user exists
type UsernameExists struct {
	UserRepo UserRepo
}

// Execute returns true on success. Username is required.
func (usecase *UsernameExists) Execute(username string) (bool, error) {
	if username == "" {
		return false, newBadRequestError("username is required")
	}

	user, err := usecase.UserRepo.GetByUsername(username)

	if err != nil {
		return false, errors.Wrap(err, "failed searching for user")
	}

	if user.Username != username {
		return false, nil
	}

	return true, nil
}

// EmailExists checks if user exists
type UserEmailExists struct {
	UserRepo UserRepo
}

// Execute returns true on success. Email is required.
func (usecase *UserEmailExists) Execute(email string) (bool, error) {
	if email == "" {
		return false, newBadRequestError("username is required")
	}

	user, err := usecase.UserRepo.GetByEmail(email)

	if err != nil {
		return false, errors.Wrap(err, "failed searching for user")
	}

	if user.Email != email {
		return false, nil
	}

	return true, nil
}

// UserInfo gets a users info
type UserInfo struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
}

// Execute returns a User struct and nil error on success. The authToken parameter is required.
// RoleConfigs is used to determine authorization to read user info.
func (usecase *UserInfo) Execute(userUUID string, authToken string) (User, error) {
	getUsers := getUserAndAuthUser{
		UserRepo:          usecase.UserRepo,
		TokenAuthenticate: usecase.TokenAuthenticate,
		RoleConfigs:       usecase.RoleConfigs,
	}

	u, authUser, err := getUsers.Execute(userUUID, authToken)

	if err != nil {
		return User{}, err
	}

	canGetInfo := false

	for _, role := range authUser.Roles {
		rc := getRoleConfig(usecase.RoleConfigs, role)
		if rc.CanGetOtherUserInfo(u, authUser) {
			canGetInfo = true
			break
		}
	}

	if !canGetInfo {
		return User{}, newAuthorizationError("unauthorized to get user info")
	}

	u.PasswordHash = ""
	return u, nil
}

// UserAssignRole assigns a new role to a user
type UserAssignRole struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
}

// Execute returns a nil error on success. Parameters username, roleSlug, & authToken are required.
// Returns error implementing Authorization() when roleSlug's RoleConfig CanAssignUserRole func returns false.
// Returns error implementing BadRequest() when user already has role.
func (usecase *UserAssignRole) Execute(userUUID string, roleSlug string, authToken string) error {
	getUsers := getUserAndAuthUser{
		UserRepo:          usecase.UserRepo,
		TokenAuthenticate: usecase.TokenAuthenticate,
		RoleConfigs:       usecase.RoleConfigs,
	}

	u, authUser, err := getUsers.Execute(userUUID, authToken)

	if err != nil {
		return err
	}

	rc := getRoleConfig(usecase.RoleConfigs, roleSlug)
	if !rc.CanAssignUserRole(u, authUser) {
		return newAuthorizationError("unauthorized to assign role")
	}

	newRoleExists := false
	for _, r := range u.Roles {
		if r == roleSlug {
			newRoleExists = true
		}
	}

	if newRoleExists {
		return newBadRequestError("role already exists")
	}

	u.Roles = append(u.Roles, roleSlug)
	err = usecase.UserRepo.Update(u)
	if err != nil {
		return errors.Wrap(err, "failed updating user")
	}

	return nil
}

// UserRemoveRole removes role from a user
type UserRemoveRole struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
}

// Execute returns a nil error on success. Parameters username, roleSlug, & authToken are required.
// Returns error implementing Authorization() when roleSlug's RoleConfig CanRemoveUserRole func returns false.
// Returns error implementing BadRequest() when user doesn't have role.
func (usecase *UserRemoveRole) Execute(userUUID string, roleSlug string, authToken string) error {
	getUsers := getUserAndAuthUser{
		UserRepo:          usecase.UserRepo,
		TokenAuthenticate: usecase.TokenAuthenticate,
		RoleConfigs:       usecase.RoleConfigs,
	}

	u, authUser, err := getUsers.Execute(userUUID, authToken)

	if err != nil {
		return err
	}

	rc := getRoleConfig(usecase.RoleConfigs, roleSlug)
	if !rc.CanRemoveUserRole(u, authUser) {
		return newAuthorizationError("unauthorized to remove role")
	}

	i := -1
	for index, r := range u.Roles {
		if r == roleSlug {
			i = index
		}
	}

	if i == -1 {
		return newBadRequestError("user doesn't have role")
	}

	//removes index from slice
	u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)

	err = usecase.UserRepo.Update(u)
	if err != nil {
		return errors.Wrap(err, "failed updating user")
	}

	return nil
}

// UserChangePassword changes a user's password
type UserChangePassword struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
	PasswordValidator Validator
	PasswordHasher    Hasher
}

// Execute returns a nil error on success. Parameters username, newPassword, authToken, & authUserPassword are required.
// Returns error implementing Authentication() when authentication failed
// Returns error implementing Authorization() when authenticated user doesn't equal user being edited AND all the authenticated user's roles CanEditUser func return false.
// Returns error implementing Authorization() when user doesn't exist. (prevents account enumeration)
func (usecase *UserChangePassword) Execute(userUUID string, newPassword string, authToken string, authUserPassword string) error {
	if userUUID == "" {
		return newBadRequestError("user UUID is required")
	}

	getUsers := getUserAndAuthUser{
		UserRepo:          usecase.UserRepo,
		TokenAuthenticate: usecase.TokenAuthenticate,
		RoleConfigs:       usecase.RoleConfigs,
	}

	u, authUser, err := getUsers.Execute(userUUID, authToken)

	if err != nil {
		return err
	}

	if authUser.PasswordHash != usecase.PasswordHasher.Hash(authUserPassword) {
		return newAuthenticationError("invalid password")
	}

	if !canEdit(u, authUser, usecase.RoleConfigs) {
		return newAuthorizationError("cannot edit user")
	}

	err = usecase.PasswordValidator.Validate(newPassword)
	if err != nil {
		return newBadRequestError(err.Error())
	}

	u.PasswordHash = usecase.PasswordHasher.Hash(newPassword)
	return errors.Wrap(usecase.UserRepo.Update(u), "failed updating user")
}

// UserSendPasswordReset send password reset email
type UserSendPasswordReset struct {
	PasswordResetMailer PasswordResetMailer
	UserRepo            UserRepo
	ResetTokenRepo      ResetTokenRepo
}

// PasswordResetMailer is used to abstract email content and sending.
type PasswordResetMailer interface {
	// resetTok is used to reset the user password
	// Returns empty resetTok when email doesn't exist
	Send(email string, resetTok string) error
}

// Execute sends a password reset token to email if exists.
// If email doesn't exist sends email to notify email doesn't exist.
// Error if email is empty or on internal server error
func (usecase *UserSendPasswordReset) Execute(email string) error {

	if email == "" {
		return newBadRequestError("email is required")
	}

	user, err := usecase.UserRepo.GetByEmail(email)

	if err != nil {
		return errors.Wrap(err, "error getting user")
	}

	if user.Email != email {
		return errors.Wrap(usecase.PasswordResetMailer.Send(email, ""), "failed sending email")
	}

	tok := ResetToken{
		UUID:       uuid.New().String(),
		UserID:     user.UUID,
		Expiration: time.Now().Add(time.Hour),
	}

	err = usecase.ResetTokenRepo.Insert(tok)

	if err != nil {
		return errors.Wrap(err, "failed inserting reset token")
	}

	return errors.Wrap(usecase.PasswordResetMailer.Send(email, tok.UUID), "failed sending email")
}

// UserInfoByResetToken is used to retrieve user by a reset token
type UserInfoByResetToken struct {
	UserRepo       UserRepo
	ResetTokenRepo ResetTokenRepo
}

// Execute returns User of Reset Token when valid
// Error implements BadRequest() when reset token is invalid.
// Otherwise error is an internal error
func (usecase *UserInfoByResetToken) Execute(resetTok string) (User, error) {
	tok, err := usecase.ResetTokenRepo.Get(resetTok)

	if err != nil {
		return User{}, errors.Wrap(err, "failed getting token")
	}

	if !tok.Valid() {
		return User{}, newBadRequestError("invalid token")
	}

	u, err := usecase.UserRepo.Get(tok.UserID)

	if err != nil {
		return User{}, errors.Wrap(err, "failed getting user")
	}

	return u, nil
}

// UserResetPassword resets a user password using a resetToken
type UserResetPassword struct {
	UserRepo          UserRepo
	ResetTokenRepo    ResetTokenRepo
	PasswordValidator Validator
	PasswordHasher    Hasher
}

// Execute returns nil on success.
// Returns error implementing BadRequest() when token invalid or password invalid.
// Otherwise returns an internal server error
func (usecase *UserResetPassword) Execute(resetToken string, newPassword string) error {

	tok, err := usecase.ResetTokenRepo.Get(resetToken)

	if err != nil {
		return errors.Wrap(err, "failed getting token")
	}

	if !tok.Valid() {
		return newBadRequestError("invalid token")
	}

	err = usecase.PasswordValidator.Validate(newPassword)
	if err != nil {
		return newBadRequestError(err.Error())
	}

	u, err := usecase.UserRepo.Get(tok.UserID)

	if err != nil {
		return errors.Wrap(err, "failed getting user")
	}

	u.PasswordHash = usecase.PasswordHasher.Hash(newPassword)

	err = usecase.UserRepo.Update(u)

	return errors.Wrap(err, "user update failed")
}

// UserChangeUsername changes a user's username
type UserChangeUsername struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
	UsernameValidator Validator
}

// Execute returns nil on success.
// Returns error implementing BadRequest() when username invalid or new username invalid.
// Returns error implementing Authentication() when authToken is invalid.
// Returns error implementing Authorization() when authenticated user doesn't equal user being edited AND all the authenticated user's roles CanEditUser func return false.
// Otherwise returns an internal server error.
func (usecase *UserChangeUsername) Execute(userUUID string, newUsername string, authToken string) error {
	if userUUID == "" {
		return newBadRequestError("user UUID is required")
	}

	if newUsername == "" {
		return newBadRequestError("must specify new username")
	}

	getUsers := getUserAndAuthUser{
		UserRepo:          usecase.UserRepo,
		TokenAuthenticate: usecase.TokenAuthenticate,
		RoleConfigs:       usecase.RoleConfigs,
	}

	u, authUser, err := getUsers.Execute(userUUID, authToken)

	if err != nil {
		return err
	}

	if !canEdit(u, authUser, usecase.RoleConfigs) {
		return newAuthorizationError("cannot edit user")
	}

	err = usecase.UsernameValidator.Validate(newUsername)
	if err != nil {
		return newBadRequestError(err.Error())
	}

	u.Username = newUsername
	return errors.Wrap(usecase.UserRepo.Update(u), "failed updating user")
}

// UserChangeEmail changes a user's email
type UserChangeEmail struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
	PasswordHasher    Hasher
}

// Execute returns nil on success.
// Returns error implementing BadRequest() when username invalid or new email invalid.
// Returns error implementing Authentication() when authToken or authUserPassword is invalid.
// Returns error implementing Authorization() when authenticated user doesn't equal user being edited AND all the authenticated user's roles CanEditUser func return false.
// Otherwise returns an internal server error.
func (usecase *UserChangeEmail) Execute(userUUID string, newEmail string, authToken string, authUserPassword string) error {
	if userUUID == "" {
		return newBadRequestError("user UUID is required")
	}

	getUsers := getUserAndAuthUser{
		UserRepo:          usecase.UserRepo,
		TokenAuthenticate: usecase.TokenAuthenticate,
		RoleConfigs:       usecase.RoleConfigs,
	}

	u, authUser, err := getUsers.Execute(userUUID, authToken)

	if err != nil {
		return err
	}

	if authUser.PasswordHash != usecase.PasswordHasher.Hash(authUserPassword) {
		return newAuthenticationError("invalid password")
	}

	if !canEdit(u, authUser, usecase.RoleConfigs) {
		return newAuthorizationError("cannot edit user")
	}

	if !validateEmail(newEmail) {
		return newBadRequestError("new email is invalid")
	}

	u.Email = newEmail
	return errors.Wrap(usecase.UserRepo.Update(u), "failed updating user")
}

type getUserAndAuthUser struct {
	UserRepo          UserRepo
	TokenAuthenticate TokenAuthenticate
	RoleConfigs       []RoleConfig
}

func (usecase *getUserAndAuthUser) Execute(userUUID string, authToken string) (user User, authenticatedUser User, error error) {
	if userUUID == "" {
		return User{}, User{}, newBadRequestError("user UUID is required")
	}

	if authToken == "" {
		return User{}, User{}, newBadRequestError("authentication token is required")
	}

	authUserID, err := usecase.TokenAuthenticate.Execute(authToken)

	if err != nil {
		return User{}, User{}, err
	}

	u, err := usecase.UserRepo.Get(userUUID)

	if err != nil {
		return User{}, User{}, errors.Wrap(err, "failed retrieving user")
	}

	if u.UUID != userUUID {
		// return AuthorizationError instead of BadRequest to it prevent account enumeration.
		return User{}, User{}, newAuthorizationError("unauthorized to get user info")
	}

	authUser, err := usecase.UserRepo.Get(authUserID)

	if err != nil {
		return User{}, User{}, errors.Wrap(err, "failed retrieving authenticated user")
	}

	return u, authUser, nil
}

// UserRepo is used for storage and retrieval of user data.
type UserRepo interface {
	//Get gets a User by their UUID
	Get(UUID string) (user User, err error)

	//GetByUsername gets a User by their username
	GetByUsername(username string) (user User, err error)

	//GetByEmail gets a User by their email
	GetByEmail(email string) (user User, err error)

	// Insert is used to add a user.
	// Will return error that implements BadRequest() upon Email or Username exists conflict.
	Insert(User) (error error)

	// Update is used to update a user. Update increments the version on every update.
	// Will return error that implements BadRequest() upon Version conflict.
	Update(User) error
}

type ResetToken struct {
	UUID       string
	UserID     string
	Expiration time.Time
}

func (tok *ResetToken) Valid() bool {
	return tok.UUID != "" && tok.UserID != "" && tok.Expiration.After(time.Now())
}

// ResetTokenRepo is used to save reset token and retrieve reset token
type ResetTokenRepo interface {
	//Insert saves a resetToken
	Insert(ResetToken) error

	//Get retrieves resetToken by UUID, returns empty resetToken when not found
	Get(UUID string) (ResetToken, error)
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

	// CanEditUser validates whether an authenticated user is allowed to edit a particular user.
	// This validates for UserChangePassword, UserChangeUsername, & UserChangeEmail.
	CanEditUser func(targetUser User, u User) bool

	// CanGetOtherUserInfo is used to validate whether an authenticated user
	// is allowed to GetInfo from another user with this role
	// if the user has multiple roles this func is ran for each role
	// checking if any returns true
	CanGetOtherUserInfo func(targetUser User, u User) bool
}

// Hasher simple interface for Hash method
type Hasher interface {
	//Hash a string
	Hash(string) string
}

func canEdit(u User, authUser User, rcs []RoleConfig) bool {
	canEdit := false

	if u.UUID == authUser.UUID {
		canEdit = true
	} else {
		for _, r := range authUser.Roles {
			c := getRoleConfig(rcs, r)
			if c.CanEditUser(u, authUser) {
				canEdit = true
				break
			}
		}
	}

	return canEdit
}

func getRoleConfig(rcs []RoleConfig, role string) RoleConfig {
	for _, r := range rcs {
		if r.Slug == role {
			return r
		}
	}

	return RoleConfig{}
}

var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func validateEmail(email string) bool {
	return rxEmail.MatchString(email)
}
