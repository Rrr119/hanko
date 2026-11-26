package models

import (
	"time"

	"github.com/gofrs/uuid"
)

type PasskeyDevice struct {
	ID         uuid.UUID  `db:"id"`
	TenantID   uuid.UUID  `db:"tenant_id"`
	UserID     uuid.UUID  `db:"user_id"`
	ParentID   string     `db:"parent_id"`
	RootID     string     `db:"root_id"`
	ReplacesID string     `db:"replaces_id"`
	Relation   string     `db:"relation"`
	Status     string     `db:"status"`
	Platform   string     `db:"platform"`
	SyncFabric string     `db:"sync_fabric"`
	Label      string     `db:"label"`
	TrustedAt  time.Time  `db:"trusted_at"`
	LastSeenAt time.Time  `db:"last_seen_at"`
	ExpiresAt  *time.Time `db:"expires_at"`
	LostAt     *time.Time `db:"lost_at"`
	RevokedAt  *time.Time `db:"revoked_at"`
	CreatedAt  time.Time  `db:"created_at"`
	UpdatedAt  time.Time  `db:"updated_at"`
}

func (PasskeyDevice) TableName() string {
	return "passkey_devices"
}

type PasskeyDeviceCredential struct {
	ID               uuid.UUID `db:"id"`
	TenantID         uuid.UUID `db:"tenant_id"`
	UserID           uuid.UUID `db:"user_id"`
	DeviceID         uuid.UUID `db:"device_id"`
	CredentialID     string    `db:"credential_id"`
	CredentialIDHash string    `db:"credential_id_hash"`
	CreatedAt        time.Time `db:"created_at"`
	UpdatedAt        time.Time `db:"updated_at"`
}

func (PasskeyDeviceCredential) TableName() string {
	return "passkey_device_credentials"
}
