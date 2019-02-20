package auth

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"time"
)

// Grant is design to centralize authorization of specific actions within microservices without storing use user authTokens.
type Grant struct {
	UUID       string
	TypeSlug   string
	UserID     string
	Expires    time.Time
	Secure     bool
	Uses       int
	UseLimit   int
	Version    int
	CustomData map[string]interface{}
}

// GrantConfig is used to create different types of Grant that can be created within the app.
type GrantConfig struct {
	// Slug is used to identity with this configuration when creating grant.
	Slug string

	// Duration defines period of use until expiration.
	Duration time.Duration

	// Limit determines how many times a grant can be used.
	// A limit set to 0 means no limit.
	Limit int

	// CanCreateGrant determines whether grant can be created.
	CanCreateGrant func(g Grant, u User, authUser User) bool

	// CanDeleteGrant determines whether grant can be deleted.
	CanDeleteGrant func(g Grant, u User, authUser User) bool

	// Secure requires re-authentication to create grant.
	Secure bool
}

// Repo is the storage interface for Grant
// The database implementation handles deleting grants once expired.
type GrantRepo interface {
	// Delete takes a UUID. Returns nil on success.
	// Returns error implementing BadRequest() when grant invalid.
	// Returns error implementing Temporary() when server error.
	// Otherwise returns a plain error implying a internal server error.
	Delete(UUID string) error

	// Create takes a valid Grant. Returns nil on success.
	// Returns error implementing BadRequest() when grant invalid.
	// Returns error implementing Temporary() when service is unavailable error.
	// Otherwise returns a plain error implying a internal server error.
	Create(Grant) error

	// Get takes a valid Grant. Returns nil on success.
	// Returns error implementing BadRequest() when grant invalid.
	// Returns error implementing Temporary() when service is unavailable error.
	// Otherwise returns a plain error implying a internal server error.
	Get(UUID string) (Grant, error)

	// Use takes a UUID. It adds a use to the grant and deletes grant once all used up.
	// The version parameter is used to be prevent distributed race conditional. DB must support atomic operations.
	// Returns error implementing BadRequest() upon grant version conflict.
	// Returns nil on success.
	// Returns error implementing Temporary() when service is unavailable error.
	// Otherwise returns a plain error implying a internal server error.
	Use(UUID string, version int) error
}

// GrantCreate is used to create a grant
type GrantCreate struct {
	GrantRepo    GrantRepo
	GrantConfigs []GrantConfig
	TokAuth      TokenAuthenticate
	UserAuth     UserAuthenticate
	UserRepo     UserRepo
}

// GrantCreateRequest is used to pass parameters for creating grant
type GrantCreateRequest struct {
	Type       string
	UserUUID   string
	AuthToken  string
	Password   string
	CustomData map[string]interface{}
}

// Execute takes a GrantCreateRequest and returns nil on success
// Returns error implementing Authentication() when unauthenticated.
// Returns error implementing BadRequest() when Password Missing When GrantConfig Secure is true.
// Returns error implementing Authorization() when GrantConfig CanCreateGrant returns false.
func (usecase *GrantCreate) Execute(createReq GrantCreateRequest) error {
	if createReq.Type == "" {
		return newBadRequestError("grant type is required")
	}

	c := getGrantConfigBySlug(createReq.Type, usecase.GrantConfigs)

	if c.CanCreateGrant == nil {
		return errors.New("invalid grant configuration")
	}

	if createReq.UserUUID == "" {
		return newBadRequestError("user uuid is required")
	}

	if createReq.AuthToken == "" {
		return newBadRequestError("authentication token is required")
	}

	user, err := usecase.UserRepo.Get(createReq.UserUUID)
	if err != nil {
		return errors.Wrap(err, "error getting user")
	}

	tokUserID, err := usecase.TokAuth.Execute(createReq.AuthToken)
	if err != nil {
		return err
	}

	authUser, err := usecase.UserRepo.Get(tokUserID)
	if err != nil {
		return errors.Wrap(err, "error getting user")
	}

	if authUser.UUID != tokUserID {
		return newAuthenticationError("invalid user credentials")
	}

	if c.Secure {
		if createReq.Password == "" {
			return newBadRequestError("password is required")
		}

		_, err := usecase.UserAuth.Execute(authUser.Username, createReq.Password)
		if err != nil {
			return errors.Wrap(err, "error authenticating user")
		}
	}

	exp := time.Now().Add(c.Duration)
	if c.Duration == 0 {
		exp = time.Time{}
	}

	g := Grant{
		UUID:       uuid.New().String(),
		UserID:     user.UUID,
		TypeSlug:   c.Slug,
		Expires:    exp,
		Secure:     c.Secure,
		UseLimit:   c.Limit,
		CustomData: createReq.CustomData,
	}

	if !c.CanCreateGrant(g, user, authUser) {
		return newAuthorizationError("unauthorized to create grant")
	}

	err = usecase.GrantRepo.Create(g)

	return errors.Wrap(err, "failed to create grant")
}

// GrantInfo is used to get grant info
type GrantInfo struct {
	GrantRepo GrantRepo
}

// Execute accepts a grant uuid and returns Grant and nil error on success.
// Returns error implementing BadRequest(), NotFound(), Authorization(), or otherwise general error
func (usecase *GrantInfo) Execute(uuid string) (Grant, error) {
	if uuid == "" {
		return Grant{}, newBadRequestError("UUID is required")
	}

	g, err := usecase.GrantRepo.Get(uuid)

	if err != nil {
		return Grant{}, errors.Wrap(err, "failed to get grant")
	}

	if g.UUID == "" {
		return Grant{}, newNotFoundError("grant not found")
	}

	if g.Expires.After(time.Now()) {
		return Grant{}, newAuthorizationError("grant has expired")
	}

	if g.Uses >= g.UseLimit {
		return Grant{}, newAuthorizationError("grant limit exceeded")
	}

	return g, nil
}

// GrantUse is used to increment grant uses
type GrantUse struct {
	GrantRepo GrantRepo
}

// Execute accepts a grant uuid and returns nil error on success.
// Returns error implementing BadRequest(), Authorization(), or otherwise general error
func (usecase *GrantUse) Execute(uuid string) error {
	getGrant := GrantInfo{GrantRepo: usecase.GrantRepo}
	g, err := getGrant.Execute(uuid)

	if IsNotFoundError(err) {
		return newAuthorizationError("grant not found")
	}

	if err != nil {
		return err
	}

	err = usecase.GrantRepo.Use(uuid, g.Version)

	return errors.Wrap(err, "failed to use grant")
}

// GrantDelete is used to delete grant
type GrantDelete struct {
	GrantRepo GrantRepo
}

// Execute accepts a grant uuid. Returns nil on success.
// Returns error implementing BadRequest() when grant invalid.
// Returns error implementing Temporary() when server error.
// Otherwise returns a plain error implying a internal server error.
func (usecase *GrantDelete) Execute(uuid string) error {
	err := usecase.GrantRepo.Delete(uuid)
	return errors.Wrap(err, "error deleting grant")
}

func getGrantConfigBySlug(typeSlug string, GrantConfigs []GrantConfig) GrantConfig {
	for _, c := range GrantConfigs {
		if c.Slug == typeSlug {
			return c
		}
	}

	return GrantConfig{}
}
