package user

// UserRepo is used for storage and retrieval of user data.
type UserRepo interface {
	// Authenticate verifies user credentials and retrieve user identifier
	// returns err that implements Authorization() if username or password is invalid
	Authenticate(username string, password string) (userID string, err error)
}
