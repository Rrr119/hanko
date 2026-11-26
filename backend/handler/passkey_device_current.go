package handler

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gobuffalo/nulls"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	hankoContext "github.com/teamhanko/hanko/backend/v3/context"
	"github.com/teamhanko/hanko/backend/v3/dto"
	"github.com/teamhanko/hanko/backend/v3/passkey/migration"
	"github.com/teamhanko/hanko/backend/v3/passkey/migrationsession"
	"github.com/teamhanko/hanko/backend/v3/persistence/models"
)

type registerCurrentPasskeyDeviceRequest struct {
	CredentialID   string `json:"credential_id" validate:"required"`
	DeviceID       string `json:"device_id" validate:"omitempty,uuid4"`
	Label          string `json:"label"`
	Platform       string `json:"platform" validate:"omitempty,oneof=apple google microsoft other"`
	SyncFabric     string `json:"sync_fabric"`
	MigrationToken string `json:"migration_token"`
}

func (h *PasskeyDeviceHandler) RegisterCurrentDevice(c echo.Context) error {
	tenant, user, err := h.authenticatedUser(c)
	if err != nil {
		return err
	}

	sessionToken, ok := c.Get("session").(jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "session required")
	}
	if !tokenHasAMR(sessionToken, "passkey") {
		return echo.NewHTTPError(http.StatusForbidden, "current session must contain a passkey authentication factor")
	}

	request := new(registerCurrentPasskeyDeviceRequest)
	if err := c.Bind(request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(request); err != nil {
		return err
	}

	credential, err := h.persister.GetWebauthnCredentialPersister().Get(request.CredentialID, tenant.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load passkey credential")
	}
	if credential == nil || credential.UserId != user.ID || credential.TenantID != tenant.ID {
		return echo.NewHTTPError(http.StatusNotFound, "passkey credential not found")
	}

	proof := migration.CredentialProof{
		ID:               credential.ID,
		AAGUID:           credential.AAGUID.String(),
		Platform:         migration.Platform(request.Platform),
		SyncFabric:       request.SyncFabric,
		BackupEligible:   credential.BackupEligible,
		BackupState:      credential.BackupState,
		UserVerified:     true,
		WebAuthnVerified: true,
	}

	var device *migration.Device
	if request.MigrationToken != "" {
		grant, err := h.store.GetGrantByTokenHash(c.Request().Context(), migration.HashToken(request.MigrationToken))
		if err != nil {
			return h.domainError(c, err)
		}
		if grant == nil || grant.TenantID != tenant.ID.String() || grant.UserID != user.ID.String() {
			return echo.NewHTTPError(http.StatusNotFound, "migration grant not found")
		}

		device, _, err = h.service.AcceptMigration(c.Request().Context(), migration.AcceptMigrationInput{
			Token:       request.MigrationToken,
			NewDeviceID: request.DeviceID,
			Label:       request.Label,
			Credential:  proof,
		})
		if err != nil {
			return h.domainError(c, err)
		}
	} else {
		device, err = h.linkSyncedCurrentDevice(c, tenant.ID.String(), user.ID.String(), request, proof)
		if err != nil {
			return err
		}
	}

	if err := h.issueDeviceSession(c, user, device); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, toPasskeyDeviceResponse(device))
}

func (h *PasskeyDeviceHandler) linkSyncedCurrentDevice(
	c echo.Context,
	tenantID string,
	userID string,
	request *registerCurrentPasskeyDeviceRequest,
	proof migration.CredentialProof,
) (*migration.Device, error) {
	ctx := c.Request().Context()

	if request.DeviceID != "" {
		existingRequestDevice, err := h.store.GetDevice(ctx, tenantID, userID, request.DeviceID)
		if err != nil {
			return nil, h.domainError(c, err)
		}
		if existingRequestDevice != nil {
			if err := h.service.AuthorizeSession(ctx, tenantID, userID, migration.SessionClaims{DeviceID: existingRequestDevice.ID}); err != nil {
				return nil, h.domainError(c, err)
			}
			return existingRequestDevice, nil
		}
	}

	anchor, err := h.store.FindDeviceByCredential(ctx, tenantID, userID, proof.ID)
	if err != nil {
		return nil, h.domainError(c, err)
	}

	switch {
	case anchor == nil:
		device, err := h.service.EnrollRoot(ctx, migration.EnrollRootInput{
			TenantID:   tenantID,
			UserID:     userID,
			DeviceID:   request.DeviceID,
			Label:      request.Label,
			Platform:   migration.Platform(request.Platform),
			SyncFabric: request.SyncFabric,
			Credential: proof,
			Legacy:     true,
		})
		if err != nil {
			return nil, h.domainError(c, err)
		}
		return device, nil

	case anchor.Status != migration.DeviceStatusActive:
		device, err := h.service.RecoverWithSyncedPasskey(ctx, migration.RecoveryInput{
			TenantID:    tenantID,
			UserID:      userID,
			NewDeviceID: request.DeviceID,
			Label:       request.Label,
			Platform:    migration.Platform(request.Platform),
			SyncFabric:  request.SyncFabric,
			Credential:  proof,
		})
		if err != nil {
			return nil, h.domainError(c, err)
		}
		return device, nil

	default:
		device, err := h.service.SyncToDevice(ctx, migration.SyncInput{
			TenantID:       tenantID,
			UserID:         userID,
			AnchorDeviceID: anchor.ID,
			NewDeviceID:    request.DeviceID,
			Label:          request.Label,
			Platform:       migration.Platform(request.Platform),
			SyncFabric:     request.SyncFabric,
			Credential:     proof,
		})
		if err != nil {
			if proof.Synced() && isRecoverableTrustChainError(err) {
				device, recoveryErr := h.service.RecoverWithSyncedPasskey(ctx, migration.RecoveryInput{
					TenantID:    tenantID,
					UserID:      userID,
					NewDeviceID: request.DeviceID,
					Label:       request.Label,
					Platform:    migration.Platform(request.Platform),
					SyncFabric:  request.SyncFabric,
					Credential:  proof,
				})
				if recoveryErr == nil {
					return device, nil
				}
			}
			return nil, h.domainError(c, err)
		}
		return device, nil
	}
}

func isRecoverableTrustChainError(err error) bool {
	return errors.Is(err, migration.ErrDeviceLost) ||
		errors.Is(err, migration.ErrDeviceRevoked) ||
		errors.Is(err, migration.ErrDeviceExpired) ||
		errors.Is(err, migration.ErrBrokenTrustChain) ||
		errors.Is(err, migration.ErrUntrustedDevice) ||
		errors.Is(err, migration.ErrTrustChainOwnerMismatch) ||
		errors.Is(err, migration.ErrDeviceNotFound)
}

func (h *PasskeyDeviceHandler) issueDeviceSession(c echo.Context, user *models.User, device *migration.Device) error {
	tenant, err := hankoContext.GetTenant(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get tenant from context")
	}
	sessionManager, err := hankoContext.GetSessionManager(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session manager from context")
	}

	claims := migration.SessionClaims{
		DeviceID:   device.ID,
		Relation:   device.Relation,
		TrustLevel: "passkey",
		Recovered:  device.Relation == migration.RelationRecovery,
	}
	tokenString, rawToken, err := sessionManager.GenerateJWT(
		dto.UserJWTFromUserModel(user),
		tenant.ID,
		migrationsession.JWTOptions(claims)...,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to issue device-bound session")
	}

	sessionID := uuid.Nil
	if value, ok := rawToken.Get("session_id"); ok {
		if valueString, ok := value.(string); ok {
			sessionID = uuid.FromStringOrNil(valueString)
		}
	}
	expiresAt := rawToken.Expiration()
	issuedAt := rawToken.IssuedAt()
	sessionModel := models.Session{
		ID:        sessionID,
		UserID:    user.ID,
		TenantID:  tenant.ID,
		CreatedAt: issuedAt,
		UpdatedAt: issuedAt,
		ExpiresAt: &expiresAt,
		LastUsed:  issuedAt,
	}
	if tenant.Config.Session.AcquireIPAddress {
		sessionModel.IpAddress = nulls.NewString(c.RealIP())
	}
	if tenant.Config.Session.AcquireUserAgent {
		sessionModel.UserAgent = nulls.NewString(c.Request().UserAgent())
	}
	if err := h.persister.GetSessionPersister().Create(sessionModel); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to persist device-bound session")
	}

	c.Response().Header().Set("X-Session-Lifetime", sessionLifetimeSeconds(tenant.Config.Session.Lifespan))
	if tenant.Config.Session.EnableAuthTokenHeader {
		c.Response().Header().Set("X-Auth-Token", tokenString)
	} else {
		cookie, err := sessionManager.GenerateCookie(tokenString)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate session cookie")
		}
		c.SetCookie(cookie)
	}
	return nil
}

func tokenHasAMR(token jwtLike, expected string) bool {
	value, ok := token.Get("amr")
	if !ok {
		return false
	}
	switch values := value.(type) {
	case []string:
		for _, candidate := range values {
			if candidate == expected {
				return true
			}
		}
	case []any:
		for _, candidate := range values {
			if candidateString, ok := candidate.(string); ok && candidateString == expected {
				return true
			}
		}
	}
	return false
}

type jwtLike interface {
	Get(string) (any, bool)
}

func sessionLifetimeSeconds(lifespan string) string {
	duration, err := time.ParseDuration(lifespan)
	if err != nil {
		return "0"
	}
	return strconv.Itoa(int(duration.Seconds()))
}
