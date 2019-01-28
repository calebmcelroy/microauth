package token

import "time"

//Token is an authentication token that is used to
//authenticate used without username and password
type Token struct {
	Token      string
	UserID     string
	Expiration time.Time
}
