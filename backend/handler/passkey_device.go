package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	hankoContext "github.com/teamhanko/hanko/backend/v3/context"
	"github.com/teamhanko/hanko/backend/v3/passkey/migration"
	"github.com/teamhanko/hanko/backend/v3/persistence"
	"github.com/teamhanko/hanko/backend/v3/persistence/models"
)

type PasskeyDeviceHandler struct {
	persister persistence.Persister
	store     migration.Store
	service   *migration.Service
}

func NewPasskeyDeviceHandler(persister persistence.Persister) *PasskeyDeviceHandler {
	store := persistence.NewPasskeyMigrationStore(persister.GetConnection())
	return NewPasskeyDeviceHandlerWithStore(persister, store)
}

func NewPasskeyDeviceHandlerWithStore(persister persistence.Persister, store migration.Store) *PasskeyDeviceHandler {
	return &PasskeyDeviceHandler{
		persister: persister,
		store:     store,
		service:   migration.NewService(store, migration.Config{}),
	}
}

type passkeyDeviceResponse struct {
	ID            string     `json:"id"`
	ParentID      string     `json:"parent_id,omitempty"`
	RootID        string     `json:"root_id"`
	ReplacesID    string     `json:"replaces_id,omitempty"`
	Relation      string     `json:"relation"`
	Status        string     `json:"status"`
	Platform      string     `json:"platform,omitempty"`
	SyncFabric    string     `json:"sync_fabric,omitempty"`
	Label         string     `json:"label,omitempty"`
	CredentialIDs []string   `json:"credential_ids"`
	TrustedAt     time.Time  `json:"trusted_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LostAt        *time.Time `json:"lost_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type createMigrationGrantRequest struct {
	SourceDeviceID   string `json:"source_device_id" validate:"required,uuid4"`
	TargetPlatform   string `json:"target_platform" validate:"omitempty,oneof=apple google microsoft other"`
	TargetSyncFabric string `json:"target_sync_fabric"`
	TTLSeconds       int    `json:"ttl_seconds" validate:"omitempty,min=60,max=3600"`
}

type migrationGrantResponse struct {
	Token            string    `json:"token,omitempty"`
	ID               string    `json:"id"`
	SourceDeviceID   string    `json:"source_device_id"`
	TargetPlatform   string    `json:"target_platform,omitempty"`
	TargetSyncFabric string    `json:"target_sync_fabric,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
}

func (h *PasskeyDeviceHandler) ListDevices(c echo.Context) error {
	tenant, user, err := h.authenticatedUser(c)
	if err != nil {
		return err
	}

	devices, err := h.store.ListDevices(c.Request().Context(), tenant.ID.String(), user.ID.String())
	if err != nil {
		return h.domainError(c, err)
	}

	response := make([]passkeyDeviceResponse, 0, len(devices))
	for _, device := range devices {
		response = append(response, toPasskeyDeviceResponse(device))
	}
	return c.JSON(http.StatusOK, response)
}

func (h *PasskeyDeviceHandler) ReportLost(c echo.Context) error {
	tenant, user, err := h.authenticatedUser(c)
	if err != nil {
		return err
	}

	deviceID := c.Param("device_id")
	if _, err := uuid.FromString(deviceID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid device_id")
	}

	device, err := h.service.ReportLost(c.Request().Context(), tenant.ID.String(), user.ID.String(), deviceID)
	if err != nil {
		return h.domainError(c, err)
	}

	return c.JSON(http.StatusOK, toPasskeyDeviceResponse(device))
}

func (h *PasskeyDeviceHandler) CreateMigrationGrant(c echo.Context) error {
	tenant, user, err := h.authenticatedUser(c)
	if err != nil {
		return err
	}

	request := new(createMigrationGrantRequest)
	if err := c.Bind(request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(request); err != nil {
		return err
	}

	var ttl time.Duration
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}

	created, err := h.service.CreateMigrationGrant(c.Request().Context(), migration.CreateGrantInput{
		TenantID:       tenant.ID.String(),
		UserID:         user.ID.String(),
		SourceDeviceID: request.SourceDeviceID,
		TargetPlatform: migration.Platform(request.TargetPlatform),
		TargetFabric:   request.TargetSyncFabric,
		TTL:            ttl,
	})
	if err != nil {
		return h.domainError(c, err)
	}

	return c.JSON(http.StatusCreated, migrationGrantResponse{
		Token:            created.Token,
		ID:               created.Grant.ID,
		SourceDeviceID:   created.Grant.SourceDeviceID,
		TargetPlatform:   string(created.Grant.TargetPlatform),
		TargetSyncFabric: created.Grant.TargetSyncFabric,
		ExpiresAt:        created.Grant.ExpiresAt,
		CreatedAt:        created.Grant.CreatedAt,
	})
}

func (h *PasskeyDeviceHandler) authenticatedUser(c echo.Context) (*hankoContext.Tenant, *models.User, error) {
	tenant, err := hankoContext.GetTenant(c)
	if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to get tenant from context")
	}

	sessionToken, ok := c.Get("session").(jwt.Token)
	if !ok {
		return nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "session required")
	}

	user, err := h.persister.GetUserPersister().GetByPublicID(uuid.FromStringOrNil(sessionToken.Subject()), tenant.ID)
	if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to get user")
	}
	if user == nil {
		return nil, nil, echo.NewHTTPError(http.StatusUnauthorized, "user not found")
	}

	return tenant, user, nil
}

func (h *PasskeyDeviceHandler) domainError(c echo.Context, err error) error {
	status := http.StatusInternalServerError
	message := "passkey device trust operation failed"

	switch {
	case errors.Is(err, migration.ErrInvalidInput):
		status = http.StatusBadRequest
		message = "invalid passkey device request"
	case errors.Is(err, migration.ErrDeviceNotFound), errors.Is(err, migration.ErrGrantNotFound):
		status = http.StatusNotFound
		message = "passkey device or migration grant not found"
	case errors.Is(err, migration.ErrDeviceLost), errors.Is(err, migration.ErrDeviceRevoked),
		errors.Is(err, migration.ErrUntrustedDevice), errors.Is(err, migration.ErrBrokenTrustChain),
		errors.Is(err, migration.ErrTrustChainOwnerMismatch), errors.Is(err, migration.ErrCrossPlatformGrantRequired):
		status = http.StatusForbidden
		message = "passkey device is not trusted"
	case errors.Is(err, migration.ErrDeviceExpired), errors.Is(err, migration.ErrGrantExpired):
		status = http.StatusGone
		message = "passkey trust or migration grant has expired"
	case errors.Is(err, migration.ErrGrantConsumed):
		status = http.StatusConflict
		message = "migration grant has already been used"
	case errors.Is(err, migration.ErrGrantRevoked):
		status = http.StatusForbidden
		message = "migration grant has been revoked"
	case errors.Is(err, migration.ErrRecoveryUnavailable), errors.Is(err, migration.ErrBackupNotAvailable):
		status = http.StatusConflict
		message = "secure passkey recovery is unavailable"
	}

	return echo.NewHTTPError(status, message).SetInternal(err)
}

func toPasskeyDeviceResponse(device *migration.Device) passkeyDeviceResponse {
	return passkeyDeviceResponse{
		ID:            device.ID,
		ParentID:      device.ParentID,
		RootID:        device.RootID,
		ReplacesID:    device.ReplacesID,
		Relation:      string(device.Relation),
		Status:        string(device.Status),
		Platform:      string(device.Platform),
		SyncFabric:    device.SyncFabric,
		Label:         device.Label,
		CredentialIDs: append([]string{}, device.CredentialIDs...),
		TrustedAt:     device.TrustedAt,
		LastSeenAt:    device.LastSeenAt,
		ExpiresAt:     device.ExpiresAt,
		LostAt:        device.LostAt,
		CreatedAt:     device.CreatedAt,
		UpdatedAt:     device.UpdatedAt,
	}
}

func (h *SessionHandler) authorizeValidatedDevice(c echo.Context, token jwt.Token, tenantID uuid.UUID) (bool, error) {
	deviceClaims := migration.SessionClaimsFromToken(token)
	if deviceClaims.DeviceID == "" {
		return true, nil
	}

	user, err := h.persister.GetUserPersister().GetByPublicID(uuid.FromStringOrNil(token.Subject()), tenantID)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}

	store := persistence.NewPasskeyMigrationStore(h.persister.GetConnection())
	service := migration.NewService(store, migration.Config{})
	err = service.AuthorizeSession(c.Request().Context(), tenantID.String(), user.ID.String(), deviceClaims)
	if err == nil {
		return true, nil
	}
	if isRecoverableTrustChainError(err) {
		return false, nil
	}
	return false, err
}
