package auth

// Validator is an interface that is used to validate
// strings for any reason such as (password, username, etc)
type Validator interface {
	Validate(string) error
}
