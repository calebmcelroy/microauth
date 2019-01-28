package token

//TokenRepo is used for storage and retrieval of tokens.
type TokenRepo interface {
	//Save a token
	Insert(Token) error

	//Get a token by string token
	Get(token string) (Token, error)

	//Delete a token by string token
	Delete(token string) error
}
