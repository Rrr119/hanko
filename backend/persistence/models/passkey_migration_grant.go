package models

import (
	"time"

	"github.com/gofrs/uuid"
)

type PasskeyMigrationGrant struct {
	ID               uuid.UUID  `db:"id"`
	TenantID         uuid.UUID  `db:"tenant_id"`
	UserID           uuid.UUID  `db:"user_id"`
	SourceDeviceID   uuid.UUID  `db:"source_device_id"`
	TokenHash        string     `db:"token_hash"`
	TargetPlatform   string     `db:"target_platform"`
	TargetSyncFabric string     `db:"target_sync_fabric"`
	ExpiresAt        time.Time  `db:"expires_at"`
	ConsumedAt       *time.Time `db:"consumed_at"`
	ConsumedDeviceID *uuid.UUID `db:"consumed_device_id"`
	RevokedAt        *time.Time `db:"revoked_at"`
	CreatedAt        time.Time  `db:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at"`
}

func (PasskeyMigrationGrant) TableName() string {
	return "passkey_migration_grants"
}
