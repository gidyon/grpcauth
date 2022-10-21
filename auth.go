package grpcauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
)

type API struct {
	signingMethod jwt.SigningMethod
	signingKey    []byte
	issuer        string
	audience      string
	adminsGroup   []string
}

// NewAPI creates a jwt authentication and authorization API using HS256 algorithm
func NewAPI(signingKey []byte, issuer, audience string) *API {

	// Validation
	switch {
	case signingKey == nil:
		panic("missing jwt signing key")
	case issuer == "":
		panic("missing jwt issuer")
	case audience == "":
		panic("missing jwt audience")
	}

	api := &API{
		signingMethod: jwt.SigningMethodHS256,
		signingKey:    signingKey,
		issuer:        issuer,
		audience:      audience,
		adminsGroup:   []string{},
	}

	return api
}

// AuthorizeGroups checks whether the claims `Group` in the context `metadata.MD Authorization JWT` is a member the allowed groups set
//
// If it's a member, `Authorization` will succeed, otherwise it will fail with `codes.PermissionDenied`.
//
// The function will attempt to extract JWT token from gRPC metadata.MD `Authorization` key from the `Context`.
//
// If getting metadata.MD object from `Context` fails i.e due to missing metadata.MD object OR missing `Authorization` key in the metadata.MD object,
// the function will fail with `codes.Unauthenticated`
//
// It is expected that before calling this method, `Authentication` ought to have happened.
func (api *API) AuthorizeGroups(ctx context.Context, groups ...string) (*Payload, error) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no claims found in token")
	}

	// check if group match
	err := matchGroup(claims.Payload.Group, groups)
	if err != nil {
		// check with roles
		err = matchGroups(claims.Roles, groups)
		if err != nil {
			return nil, err
		}
	}

	return claims.Payload, nil
}

// AuthorizeIds checks whether the claims `Id` in the context `metadata.MD Authorization JWT` is a member the allowed Ids set
//
// If it's a member, `Authorization` will succeed, otherwise it will fail with `codes.PermissionDenied`.
//
// The function will attempt to extract JWT token from gRPC metadata.MD `Authorization` key from the `Context`.
//
// If getting metadata.MD object from `Context` fails i.e due to missing metadata.MD object OR missing `Authorization` key in the metadata.MD object,
// the function will fail with `codes.Unauthenticated`
//
// It is expected that before calling this method, `Authentication` ought to have happened.
func (api *API) AuthorizeIds(ctx context.Context, ids ...string) (*Payload, error) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no claims found in token")
	}

	for _, id := range ids {
		if claims.ID == id {
			return claims.Payload, nil
		}
	}

	return nil, status.Errorf(codes.PermissionDenied, "permission denied for actors ids [%s]", strings.Join(ids, ", "))
}

// AdminGroups retrieves `Admins groups` registered.
func (api *API) AdminGroups() []string {
	v := make([]string, 0, len(api.adminsGroup))
	v = append(v, api.adminsGroup...)
	return v
}

// IsAdmin checks whether the provided `gruop` belongs to the `Admins group`.
func (api *API) IsAdmin(group string) bool {
	return matchGroup(group, api.adminsGroup) == nil
}

// GenToken generates JWT token with given `payload` that expire after `expirationTime` elapses.
//
// It uses the receivers `SigningMethod` and `SigningKey` to sign the token.
func (api *API) GenToken(ctx context.Context, payload *Payload, expirationTime time.Time) (string, error) {
	return api.genToken(ctx, payload, expirationTime.Unix())
}

// GenTokenUsingKey generates JWT token with given `payload` that expire after `expirationTime` elapses.
//
// It uses the provided `signingKey` and the receiver `SigningMethod` to sign the token.
func (api *API) GenTokenUsingKey(ctx context.Context, claims *Claims, expirationTime time.Time, signingKey []byte) (string, error) {
	return api.genTokenV2(ctx, claims, expirationTime.Unix(), signingKey)
}

// GenTokenFromClaims generates JWT token with given `claims` that expire after `expirationTime` elapses.
//
// It uses the receivers `SigningMethod` and `SigningKey` to sign the token.
func (api *API) GenTokenFromClaims(ctx context.Context, claims *Claims, expirationTime time.Time) (string, error) {
	return api.genTokenV2(ctx, claims, expirationTime.Unix(), api.signingKey)
}

// GetClaims retrives claims by reading the value of `claimsKey` in the `Context`
func (api *API) GetClaims(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no claims found in token")
	}

	return claims, nil
}

// GetClaimsFromJwt retrives claims by parsing the `jwt` string.
//
// It uses the reciever `SigningKey` during parsing.
func (api *API) GetClaimsFromJwt(jwt string) (*Claims, error) {
	claims, err := api.parseToken(jwt)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// GetMetadataFromJwt creates a metadata.MD object from `jwt` string.
func (api *API) GetMetadataFromJwt(jwt string) (metadata.MD, error) {
	return metadata.Pairs(Header(), fmt.Sprintf("%s %s", Scheme(), jwt)), nil
}

// GetMetadataFromCtx retrieves metadata.MD object from `Context`
func (api *API) GetMetadataFromCtx(ctx context.Context) (metadata.MD, error) {
	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, err
	}
	return metadata.Pairs(Header(), fmt.Sprintf("%s %s", Scheme(), token)), nil
}

// Authenticator is the function that performs authentication
//
// The passed in `Context` will contain the gRPC metadata.MD object (for header-based authentication) and
// the peer.Peer information that can contain transport-based credentials (e.g. `credentials.AuthInfo`).
//
// The returned context will be propagated to handlers, allowing user changes to `Context`. However,
// please make sure that the `Context` returned is a child `Context` of the one passed in.
//
// If error is returned, its `grpc.Code()` will be returned to the user as well as the verbatim message.
// Please make sure you use `codes.Unauthenticated` (lacking auth) and `codes.PermissionDenied`
func (api *API) Authenticator(ctx context.Context) (context.Context, error) {
	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, err
	}

	claims, err := api.parseToken(token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
	}

	grpc_ctxtags.Extract(ctx).Set("auth.sub", userClaimFromToken(claims))

	return context.WithValue(ctx, claimsKey, claims), nil
}

func userClaimFromToken(claims *Claims) *Payload {
	return claims.Payload
}

// parses a jwt token and return claims or error if token is invalid
func (api *API) parseToken(tokenString string) (claims *Claims, err error) {
	// Handling any panic is good trust me!
	defer func() {
		if err2 := recover(); err2 != nil {
			err = fmt.Errorf("%v", err2)
		}
	}()

	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return api.signingKey, nil
		},
	)
	if err != nil {
		return nil, status.Errorf(
			codes.Unauthenticated, "failed to parse token with claims: %v", err,
		)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "JWT is not valid")
	}
	return claims, nil
}

type claims string

// claimsKey holds the context key containing the token information
const claimsKey = claims("claims")

func matchGroup(claimGroup string, groups []string) error {
	for _, group := range groups {
		if claimGroup == group {
			return nil
		}
	}
	return status.Errorf(codes.PermissionDenied, "permission denied for group %s", claimGroup)
}

func matchGroups(claimGroups []string, groups []string) error {
	for _, group := range groups {
		for _, claimGroup := range claimGroups {
			if claimGroup == group {
				return nil
			}
		}
	}
	return status.Errorf(codes.PermissionDenied, "permission denied for groups %s", strings.Join(claimGroups, ","))
}
