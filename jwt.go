package grpcauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// Payload contains jwt payload
type Payload struct {
	ID           string
	ProjectID    string
	Names        string
	PhoneNumber  string
	EmailAddress string
	Group        string
	Roles        []string
}

// Claims contains JWT claims information
type Claims struct {
	*Payload
	jwt.StandardClaims
}

func (api *API) genToken(ctx context.Context, payload *Payload, expires int64) (tokenStr string, err error) {
	defer func() {
		if err2 := recover(); err2 != nil {
			err = fmt.Errorf("%v", err2)
		}
	}()

	token := jwt.NewWithClaims(api.signingMethod, Claims{
		Payload: payload,
		StandardClaims: jwt.StandardClaims{
			Audience:  api.audience,
			ExpiresAt: expires,
			IssuedAt:  time.Now().Unix(),
			Issuer:    api.issuer,
			NotBefore: 0,
			Subject:   "",
		},
	})

	token.Header["kid"] = payload.ProjectID

	return token.SignedString(api.signingKey)
}

func (api *API) genTokenV2(ctx context.Context, claims *Claims, expires int64, signingKey []byte) (tokenStr string, err error) {
	defer func() {
		if err2 := recover(); err2 != nil {
			err = fmt.Errorf("%v", err2)
		}
	}()

	token := jwt.NewWithClaims(api.signingMethod, *claims)

	token.Header["kid"] = claims.ProjectID

	return token.SignedString(signingKey)
}

// Scheme returns authentication scheme
func Scheme() string {
	return "Bearer"
}

// Header returns authentication header
func Header() string {
	return "authorization"
}

// DefaultAdminGroups returns the default administrators group
func DefaultAdminGroups() []string {
	return []string{DefaultAdminGroup(), DefaultSuperAdminGroup()}
}

// DefaultUserGroup is the default user group
func DefaultUserGroup() string {
	return "USER"
}

// DefaultAdminGroup is the default admin group
func DefaultAdminGroup() string {
	return "ADMIN"
}

// DefaultSuperAdminGroup is the default super admin group
func DefaultSuperAdminGroup() string {
	return "SUPER_ADMIN"
}
