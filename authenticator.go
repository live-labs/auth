package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

// Authenticator is a middleware that checks if the user is authenticated and has the required roles
// If the user is not authenticated or does not have the required roles, the middleware returns 401
// If the user is authenticated and has the required roles, the middleware calls the next handler
// The middleware expects the Authorization header to contain a valid JWT token, e.g.:
// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
// The middleware expects the JWT token to contain a "roles" claim, e.g.:
//
//	`{
//	  "roles": "admin,user"
//	}`
//
// The middleware expects the JWT token to be signed with HMAC and the secret must be provided
// roles is a comma separated list of roles
// if "admin" is present in the roles list, the user is allowed to access all endpoints,
// otherwise the user must have at least one of the required roles.
type Authenticator struct {
	secret string
}

// NewAuthenticator creates a new Authenticator
// secret is the secret used to sign the JWT token
func NewAuthenticator(secret string) *Authenticator {
	return &Authenticator{
		secret: secret,
	}
}

// Wrap wraps the next handler and checks if the user is authenticated and has the required roles
func (a *Authenticator) Wrap(next http.HandlerFunc, requiredRoles ...string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {

		hdr := request.Header.Get("Authorization")
		if hdr == "" {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Unauthorized"))
			return
		}

		if !strings.HasPrefix(hdr, "Bearer ") {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Bearer authorization expected"))
			return
		}

		hdr, _ = strings.CutPrefix(hdr, "Bearer ")

		token, err := jwt.Parse(hdr, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return []byte(a.secret), nil
		})

		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Bad request, invalid signing method"))
			return
		}

		if !token.Valid {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Invalid token"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Invalid claims"))
			return
		}

		roles := claims["roles"]
		if roles == nil {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("No roles"))
			return
		}

		rolesStr, ok := roles.(string)
		if !ok {
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write([]byte("Invalid role list type"))
			return
		}

		roleList := NewRoleSet()
		roleList.LoadFrom(rolesStr)

		// Check if the user has admin role -> if yes, allow access to all endpoints
		if roleList.Has(RoleAdmin) {
			next(writer, request)
			return
		}

		// Check if the user has any of the required roles
		if roleList.HasAny(requiredRoles) {
			next(writer, request)
			return
		}

		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Unauthorized"))

	}
}
