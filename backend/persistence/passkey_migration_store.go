package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/hanko/backend/v3/passkey/migration"
	"github.com/teamhanko/hanko/backend/v3/persistence/models"
)

var _ migration.Store = (*PasskeyMigrationStore)(nil)

// PasskeyMigrationStore adapts the Passkey device-chain domain store to Pop.
type PasskeyMigrationStore struct {
	db *pop.Connection
}

func NewPasskeyMigrationStore(db *pop.Connection) *PasskeyMigrationStore {
	return &PasskeyMigrationStore{db: db}
}

func (s *PasskeyMigrationStore) SaveDevice(_ context.Context, device *migration.Device) error {
	deviceModel, err := toPasskeyDeviceModel(device)
	if err != nil {
		return err
	}

	if err := s.db.Save(deviceModel); err != nil {
		return fmt.Errorf("save passkey device: %w", err)
	}

	existingCredentials := []models.PasskeyDeviceCredential{}
	if err := s.db.Where("device_id = ?", deviceModel.ID).All(&existingCredentials); err != nil {
		return fmt.Errorf("load passkey device credentials: %w", err)
	}
	for i := range existingCredentials {
		if err := s.db.Destroy(&existingCredentials[i]); err != nil {
			return fmt.Errorf("replace passkey device credentials: %w", err)
		}
	}

	for _, credentialID := range device.CredentialIDs {
		credentialModel := models.PasskeyDeviceCredential{
			ID:               uuid.Must(uuid.NewV4()),
			TenantID:         deviceModel.TenantID,
			UserID:           deviceModel.UserID,
			DeviceID:         deviceModel.ID,
			CredentialID:     credentialID,
			CredentialIDHash: hashCredentialID(credentialID),
			CreatedAt:        device.CreatedAt,
			UpdatedAt:        device.UpdatedAt,
		}
		if err := s.db.Create(&credentialModel); err != nil {
			return fmt.Errorf("save passkey device credential link: %w", err)
		}
	}

	return nil
}

func (s *PasskeyMigrationStore) GetDevice(ctx context.Context, tenantID, userID, deviceID string) (*migration.Device, error) {
	tenantUUID, userUUID, deviceUUID, err := parsePrincipalAndDevice(tenantID, userID, deviceID)
	if err != nil {
		return nil, err
	}

	deviceModel := models.PasskeyDevice{}
	query := s.db.Where("tenant_id = ? AND user_id = ? AND id = ?", tenantUUID, userUUID, deviceUUID)
	err = query.First(&deviceModel)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get passkey device: %w", err)
	}

	credentialModels, err := s.deviceCredentials(deviceModel.ID)
	if err != nil {
		return nil, err
	}
	return toMigrationDevice(&deviceModel, credentialModels), nil
}

func (s *PasskeyMigrationStore) FindDeviceByCredential(ctx context.Context, tenantID, userID, credentialID string) (*migration.Device, error) {
	tenantUUID, err := uuid.FromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", migration.ErrInvalidInput)
	}
	userUUID, err := uuid.FromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", migration.ErrInvalidInput)
	}

	credentialLink := models.PasskeyDeviceCredential{}
	err = s.db.
		Where("tenant_id = ? AND user_id = ? AND credential_id_hash = ?", tenantUUID, userUUID, hashCredentialID(credentialID)).
		Order("created_at DESC").
		First(&credentialLink)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find passkey device by credential: %w", err)
	}

	return s.GetDevice(ctx, tenantID, userID, credentialLink.DeviceID.String())
}

func (s *PasskeyMigrationStore) ListDevices(_ context.Context, tenantID, userID string) ([]*migration.Device, error) {
	tenantUUID, err := uuid.FromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", migration.ErrInvalidInput)
	}
	userUUID, err := uuid.FromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", migration.ErrInvalidInput)
	}

	deviceModels := []models.PasskeyDevice{}
	if err := s.db.Where("tenant_id = ? AND user_id = ?", tenantUUID, userUUID).Order("created_at ASC").All(&deviceModels); err != nil {
		return nil, fmt.Errorf("list passkey devices: %w", err)
	}

	devices := make([]*migration.Device, 0, len(deviceModels))
	for i := range deviceModels {
		credentials, err := s.deviceCredentials(deviceModels[i].ID)
		if err != nil {
			return nil, err
		}
		devices = append(devices, toMigrationDevice(&deviceModels[i], credentials))
	}
	return devices, nil
}

func (s *PasskeyMigrationStore) SaveGrant(_ context.Context, grant *migration.MigrationGrant) error {
	grantModel, err := toGrantModel(grant)
	if err != nil {
		return err
	}
	if err := s.db.Save(grantModel); err != nil {
		return fmt.Errorf("save passkey migration grant: %w", err)
	}
	return nil
}

func (s *PasskeyMigrationStore) GetGrantByTokenHash(_ context.Context, tokenHash string) (*migration.MigrationGrant, error) {
	grantModel := models.PasskeyMigrationGrant{}
	err := s.db.Where("token_hash = ?", tokenHash).First(&grantModel)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get passkey migration grant: %w", err)
	}
	return toMigrationGrant(&grantModel), nil
}

func (s *PasskeyMigrationStore) ConsumeGrant(_ context.Context, tokenHash, consumedDeviceID string, at time.Time) (*migration.MigrationGrant, error) {
	deviceUUID, err := uuid.FromString(consumedDeviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid consumed device id", migration.ErrInvalidInput)
	}

	var result *migration.MigrationGrant
	err = s.db.Transaction(func(tx *pop.Connection) error {
		grantModel := models.PasskeyMigrationGrant{}
		err := tx.RawQuery("SELECT * FROM passkey_migration_grants WHERE token_hash = ? FOR UPDATE", tokenHash).First(&grantModel)
		if err != nil && errors.Is(err, sql.ErrNoRows) {
			return migration.ErrGrantNotFound
		}
		if err != nil {
			return fmt.Errorf("lock passkey migration grant: %w", err)
		}

		grant := toMigrationGrant(&grantModel)
		if err := grant.Pending(at); err != nil {
			return err
		}

		grantModel.ConsumedAt = &at
		grantModel.ConsumedDeviceID = &deviceUUID
		grantModel.UpdatedAt = at
		if err := tx.Save(&grantModel); err != nil {
			return fmt.Errorf("consume passkey migration grant: %w", err)
		}

		result = toMigrationGrant(&grantModel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *PasskeyMigrationStore) RevokePendingGrantsFromDevice(_ context.Context, tenantID, userID, deviceID string, at time.Time) error {
	tenantUUID, userUUID, deviceUUID, err := parsePrincipalAndDevice(tenantID, userID, deviceID)
	if err != nil {
		return err
	}

	grants := []models.PasskeyMigrationGrant{}
	err = s.db.
		Where("tenant_id = ? AND user_id = ? AND source_device_id = ?", tenantUUID, userUUID, deviceUUID).
		Where("consumed_at IS NULL").
		Where("revoked_at IS NULL").
		All(&grants)
	if err != nil {
		return fmt.Errorf("list pending passkey migration grants: %w", err)
	}

	for i := range grants {
		grants[i].RevokedAt = &at
		grants[i].UpdatedAt = at
		if err := s.db.Save(&grants[i]); err != nil {
			return fmt.Errorf("revoke passkey migration grant: %w", err)
		}
	}
	return nil
}

func (s *PasskeyMigrationStore) deviceCredentials(deviceID uuid.UUID) ([]models.PasskeyDeviceCredential, error) {
	credentials := []models.PasskeyDeviceCredential{}
	if err := s.db.Where("device_id = ?", deviceID).Order("created_at ASC").All(&credentials); err != nil {
		return nil, fmt.Errorf("list passkey device credentials: %w", err)
	}
	return credentials, nil
}

func parsePrincipalAndDevice(tenantID, userID, deviceID string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	tenantUUID, err := uuid.FromString(tenantID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: invalid tenant id", migration.ErrInvalidInput)
	}
	userUUID, err := uuid.FromString(userID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: invalid user id", migration.ErrInvalidInput)
	}
	deviceUUID, err := uuid.FromString(deviceID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: invalid device id", migration.ErrInvalidInput)
	}
	return tenantUUID, userUUID, deviceUUID, nil
}

func toPasskeyDeviceModel(device *migration.Device) (*models.PasskeyDevice, error) {
	id, err := uuid.FromString(device.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid device id", migration.ErrInvalidInput)
	}
	tenantID, err := uuid.FromString(device.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", migration.ErrInvalidInput)
	}
	userID, err := uuid.FromString(device.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", migration.ErrInvalidInput)
	}

	return &models.PasskeyDevice{
		ID:         id,
		TenantID:   tenantID,
		UserID:     userID,
		ParentID:   device.ParentID,
		RootID:     device.RootID,
		ReplacesID: device.ReplacesID,
		Relation:   string(device.Relation),
		Status:     string(device.Status),
		Platform:   string(device.Platform),
		SyncFabric: device.SyncFabric,
		Label:      device.Label,
		TrustedAt:  device.TrustedAt,
		LastSeenAt: device.LastSeenAt,
		ExpiresAt:  device.ExpiresAt,
		LostAt:     device.LostAt,
		RevokedAt:  device.RevokedAt,
		CreatedAt:  device.CreatedAt,
		UpdatedAt:  device.UpdatedAt,
	}, nil
}

func toMigrationDevice(model *models.PasskeyDevice, credentials []models.PasskeyDeviceCredential) *migration.Device {
	credentialIDs := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		credentialIDs = append(credentialIDs, credential.CredentialID)
	}
	return &migration.Device{
		ID:            model.ID.String(),
		TenantID:      model.TenantID.String(),
		UserID:        model.UserID.String(),
		ParentID:      model.ParentID,
		RootID:        model.RootID,
		ReplacesID:    model.ReplacesID,
		Relation:      migration.Relation(model.Relation),
		Status:        migration.DeviceStatus(model.Status),
		Platform:      migration.Platform(model.Platform),
		SyncFabric:    model.SyncFabric,
		Label:         model.Label,
		CredentialIDs: credentialIDs,
		TrustedAt:     model.TrustedAt,
		LastSeenAt:    model.LastSeenAt,
		ExpiresAt:     model.ExpiresAt,
		LostAt:        model.LostAt,
		RevokedAt:     model.RevokedAt,
		CreatedAt:     model.CreatedAt,
		UpdatedAt:     model.UpdatedAt,
	}
}

func toGrantModel(grant *migration.MigrationGrant) (*models.PasskeyMigrationGrant, error) {
	id, err := uuid.FromString(grant.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid grant id", migration.ErrInvalidInput)
	}
	tenantID, err := uuid.FromString(grant.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", migration.ErrInvalidInput)
	}
	userID, err := uuid.FromString(grant.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", migration.ErrInvalidInput)
	}
	sourceDeviceID, err := uuid.FromString(grant.SourceDeviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source device id", migration.ErrInvalidInput)
	}

	var consumedDeviceID *uuid.UUID
	if grant.ConsumedDeviceID != "" {
		parsed, err := uuid.FromString(grant.ConsumedDeviceID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid consumed device id", migration.ErrInvalidInput)
		}
		consumedDeviceID = &parsed
	}

	return &models.PasskeyMigrationGrant{
		ID:               id,
		TenantID:         tenantID,
		UserID:           userID,
		SourceDeviceID:   sourceDeviceID,
		TokenHash:        grant.TokenHash,
		TargetPlatform:   string(grant.TargetPlatform),
		TargetSyncFabric: grant.TargetSyncFabric,
		ExpiresAt:        grant.ExpiresAt,
		ConsumedAt:       grant.ConsumedAt,
		ConsumedDeviceID: consumedDeviceID,
		RevokedAt:        grant.RevokedAt,
		CreatedAt:        grant.CreatedAt,
		UpdatedAt:        grant.UpdatedAt,
	}, nil
}

func toMigrationGrant(model *models.PasskeyMigrationGrant) *migration.MigrationGrant {
	grant := &migration.MigrationGrant{
		ID:               model.ID.String(),
		TenantID:         model.TenantID.String(),
		UserID:           model.UserID.String(),
		SourceDeviceID:   model.SourceDeviceID.String(),
		TokenHash:        model.TokenHash,
		TargetPlatform:   migration.Platform(model.TargetPlatform),
		TargetSyncFabric: model.TargetSyncFabric,
		ExpiresAt:        model.ExpiresAt,
		ConsumedAt:       model.ConsumedAt,
		RevokedAt:        model.RevokedAt,
		CreatedAt:        model.CreatedAt,
		UpdatedAt:        model.UpdatedAt,
	}
	if model.ConsumedDeviceID != nil {
		grant.ConsumedDeviceID = model.ConsumedDeviceID.String()
	}
	return grant
}

func hashCredentialID(credentialID string) string {
	sum := sha256.Sum256([]byte(credentialID))
	return hex.EncodeToString(sum[:])
}
