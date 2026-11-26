package middleware

import (
	"errors"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	hankoContext "github.com/teamhanko/hanko/backend/v3/context"
	"github.com/teamhanko/hanko/backend/v3/passkey/migration"
	"github.com/teamhanko/hanko/backend/v3/persistence"
)

// PasskeyDeviceSession enforces current device-chain status only for sessions
// that contain the optional did claim. Legacy sessions without did are passed
// through; normal JWT verification, database session checks, and revocation
// still run in the ordinary Session middleware.
func PasskeyDeviceSession(persister persistence.Persister) echo.MiddlewareFunc {
	store := persistence.NewPasskeyMigrationStore(persister.GetConnection())
	service := migration.NewService(store, migration.Config{})

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token, ok := c.Get("session").(jwt.Token)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "session required")
			}

			claims := migration.SessionClaimsFromToken(token)
			if claims.DeviceID == "" {
				return next(c)
			}

			tenant, err := hankoContext.GetTenant(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to get tenant from context")
			}

			user, err := persister.GetUserPersister().GetByPublicID(uuid.FromStringOrNil(token.Subject()), tenant.ID)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to resolve session user")
			}
			if user == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "user not found")
			}

			err = service.AuthorizeSession(c.Request().Context(), tenant.ID.String(), user.ID.String(), claims)
			if err != nil {
				if isDeviceTrustRejection(err) {
					return echo.NewHTTPError(http.StatusUnauthorized, "passkey device is no longer trusted").SetInternal(err)
				}
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to verify passkey device trust").SetInternal(err)
			}

			return next(c)
		}
	}
}

func isDeviceTrustRejection(err error) bool {
	return errors.Is(err, migration.ErrDeviceNotFound) ||
		errors.Is(err, migration.ErrDeviceInactive) ||
		errors.Is(err, migration.ErrDeviceLost) ||
		errors.Is(err, migration.ErrDeviceRevoked) ||
		errors.Is(err, migration.ErrDeviceExpired) ||
		errors.Is(err, migration.ErrUntrustedDevice) ||
		errors.Is(err, migration.ErrBrokenTrustChain) ||
		errors.Is(err, migration.ErrTrustChainOwnerMismatch)
}
