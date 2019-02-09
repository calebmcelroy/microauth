package auth

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"time"
)

// Token is an authentication auth that is used to
// authenticate used without username and password
type Token struct {
	Token      string
	UserID     string
	Expiration time.Time
}

// TokenRepo is used for storage and retrieval of tokens.
type TokenRepo interface {
	// Insert an auth token
	Insert(Token) error

	// Get an auth token by string token
	Get(token string) (Token, error)

	// Delete an auth token
	Delete(token string) error

	// GetByUser retrieves all tokens for a user
	GetByUser(userID string) ([]Token, error)
}

// TokenCreate usecase is used to create a auth for a user
type TokenCreate struct {
	UserAuthenticate UserAuthenticate
	TokenRepo        TokenRepo
}

// Execute is used to run the usecase
func (u TokenCreate) Execute(username string, password string, remember bool) (token Token, err error) {
	if username == "" || password == "" {
		return Token{}, newBadRequestError("Username and password are required")
	}

	userID, credsErr := u.UserAuthenticate.Execute(username, password)

	if credsErr != nil {
		return Token{}, credsErr
	}

	t := Token{}
	t.Token = uuid.New().String()
	t.UserID = userID

	if remember {
		t.Expiration = time.Now().Add(time.Hour * 24 * 30)
	} else {
		t.Expiration = time.Now().Add(time.Hour * 24)
	}

	repoErr := u.TokenRepo.Insert(t)

	if repoErr != nil {
		return Token{}, errors.Wrap(repoErr, "insert auth failed")
	}

	return t, nil
}

// TokenDelete is used to delete a user auth auth if a user auth auth is passed
type TokenDelete struct {
	TokenAuthenticate TokenAuthenticate
	TokenRepo         TokenRepo
}

// Execute returns nil if the "deleteToken" param was successfully deleted.
// Otherwise it returns a error. err.Authentication() if not authenticated.
// err.Authorization() if not authorized to delete auth.
func (u TokenDelete) Execute(deleteToken string, authToken string) error {
	userID, err := u.TokenAuthenticate.Execute(authToken)

	if err != nil {
		return err
	}

	t, err := u.TokenRepo.Get(deleteToken)
	if err != nil {
		return errors.Wrap(err, "retrieving delete auth failed")
	}

	if (t == Token{}) {
		return newNotFoundError("auth not found")
	}

	if t.UserID != userID {
		return newAuthorizationError("you are not authorized to delete this auth")
	}

	err = errors.Wrap(u.TokenRepo.Delete(deleteToken), "error deleting auth")

	return err
}

// GetUserTokens is used to retrieve a user's tokens
type GetUserTokens struct {
	TokenRepo         TokenRepo
	TokenAuthenticate TokenAuthenticate
}

// GetUserTokens returns []Token if authenticated.
// An authorization error is returned if authToken invalid.
// Otherwise error represents internal error.
func (u GetUserTokens) Execute(authToken string) ([]Token, error) {
	if authToken == "" {
		return nil, newAuthenticationError("missing auth auth")
	}

	userID, err := u.TokenAuthenticate.Execute(authToken)
	if err != nil {
		return nil, err
	}

	tokens, err := u.TokenRepo.GetByUser(userID)
	return tokens, errors.Wrap(err, "failed getting tokens")
}

// TokenAuthenticate is used to verify if authToken is valid and gets the current user
type TokenAuthenticate struct {
	TokenRepo TokenRepo
}

// Execute returns userID if success. Returns authentication error if invalid.
func (u TokenAuthenticate) Execute(token string) (userID string, error error) {
	t, err := u.TokenRepo.Get(token)

	if err != nil {
		return "", errors.Wrap(err, "failed getting auth")
	}

	tokenExpired := time.Now().After(t.Expiration)
	tokenMatches := t.Token == token
	tokenUserEmpty := t.UserID == ""

	if tokenExpired || !tokenMatches || tokenUserEmpty {
		return "", newAuthenticationError("invalid auth")
	}

	return t.UserID, nil
}
