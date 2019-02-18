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

	// Use takes a UUID. It adds a use to the grant and deletes grant once all used up.
	// Returns nil on success.
	// Returns error implementing Temporary() when service is unavailable error.
	// Otherwise returns a plain error implying a internal server error.
	Use(UUID string) error
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

	g := Grant{
		UUID:       uuid.New().String(),
		UserID:     user.UUID,
		TypeSlug:   c.Slug,
		Expires:    time.Now().Add(c.Duration),
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

func getGrantConfigBySlug(typeSlug string, GrantConfigs []GrantConfig) GrantConfig {
	for _, c := range GrantConfigs {
		if c.Slug == typeSlug {
			return c
		}
	}

	return GrantConfig{}
}
