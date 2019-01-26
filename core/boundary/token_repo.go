package boundary

import "github.com/calebmcelroy/tradelead-auth/core/entity"

//TokenRepo is used for storage and retrieval of tokens.
type TokenRepo interface {
	//Save a token
	Insert(entity.Token) error

	//Get a token by string token
	Get(token string) (entity.Token, error)

	//Delete a token by string token
	Delete(token string) error
}
