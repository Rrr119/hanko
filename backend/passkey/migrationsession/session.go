// Package migrationsession adapts Passkey device-chain claims to Hanko's
// existing session manager.
package migrationsession

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/teamhanko/hanko/backend/v3/dto"
	"github.com/teamhanko/hanko/backend/v3/passkey/migration"
	"github.com/teamhanko/hanko/backend/v3/session"
)

// JWTOptions converts device-chain claims into existing JWT options.
func JWTOptions(claims migration.SessionClaims) []session.JWTOptions {
	values := claims.ClaimMap()
	options := make([]session.JWTOptions, 0, len(values))
	for key, value := range values {
		options = append(options, session.WithValue(key, value))
	}
	return options
}

// Issue creates the same signed JWT and cookie used by the existing session
// system. Recovery/migration only adds optional claims and does not introduce a
// second session type.
func Issue(manager session.Manager, user dto.UserJWT, tenantID uuid.UUID, claims migration.SessionClaims) (string, jwt.Token, *http.Cookie, error) {
	tokenString, rawToken, err := manager.GenerateJWT(user, tenantID, JWTOptions(claims)...)
	if err != nil {
		return "", nil, nil, err
	}
	cookie, err := manager.GenerateCookie(tokenString)
	if err != nil {
		return "", nil, nil, err
	}
	return tokenString, rawToken, cookie, nil
}
