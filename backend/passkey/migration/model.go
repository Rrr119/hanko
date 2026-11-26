// Package migration implements Passkey device lineage, cross-device transfer
// decisions, and loss/recovery policy.
//
// It deliberately does not implement Passkey private-key export: platform and
// cross-platform authenticators own synchronization/transfer. Hanko verifies
// the resulting WebAuthn assertion or attestation and then decides whether the
// device relationship is trustworthy.
package migration

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidInput               = errors.New("invalid passkey migration input")
	ErrWebAuthnNotVerified        = errors.New("webauthn response has not been verified")
	ErrUserVerificationRequired   = errors.New("user verification is required for passkey migration")
	ErrBackupNotAvailable         = errors.New("passkey is not backed up and eligible for synchronization")
	ErrDeviceNotFound             = errors.New("passkey device not found")
	ErrDeviceInactive             = errors.New("passkey device is not active")
	ErrDeviceLost                 = errors.New("passkey device was reported lost")
	ErrDeviceRevoked              = errors.New("passkey device was revoked")
	ErrDeviceExpired              = errors.New("passkey device trust has expired")
	ErrUntrustedDevice            = errors.New("passkey device is not trusted")
	ErrBrokenTrustChain           = errors.New("passkey device trust chain is broken")
	ErrTrustChainOwnerMismatch    = errors.New("passkey device trust chain crosses user or tenant boundary")
	ErrCrossPlatformGrantRequired = errors.New("cross-platform passkey migration requires a one-time grant")
	ErrGrantNotFound              = errors.New("passkey migration grant not found")
	ErrGrantInvalid               = errors.New("passkey migration grant is invalid")
	ErrGrantExpired               = errors.New("passkey migration grant has expired")
	ErrGrantConsumed              = errors.New("passkey migration grant has already been used")
	ErrGrantRevoked               = errors.New("passkey migration grant has been revoked")
	ErrRecoveryUnavailable        = errors.New("no secure passkey recovery path is available")
)

type DeviceStatus string

const (
	DeviceStatusActive  DeviceStatus = "active"
	DeviceStatusLost    DeviceStatus = "lost"
	DeviceStatusRevoked DeviceStatus = "revoked"
)

type Relation string

const (
	// RelationRoot is the first independently trusted device.
	RelationRoot Relation = "root"
	// RelationLegacyRoot bootstraps a chain for a credential that existed before device tracking.
	RelationLegacyRoot Relation = "legacy_root"
	// RelationSamePlatformSync means the same platform sync fabric made the backed-up credential available.
	RelationSamePlatformSync Relation = "same_platform_sync"
	// RelationCrossPlatformMigration means an existing trusted device approved a one-time transfer.
	RelationCrossPlatformMigration Relation = "cross_platform_migration"
	// RelationRecovery is a new root established after loss using a healthy synced credential.
	RelationRecovery Relation = "recovery"
)

type Platform string

const (
	PlatformApple     Platform = "apple"
	PlatformGoogle    Platform = "google"
	PlatformMicrosoft Platform = "microsoft"
	PlatformOther     Platform = "other"
)

// CredentialProof is the policy-relevant subset of a successfully verified
// WebAuthn response. WebAuthnVerified must only be set by an adapter that has
// executed the go-webauthn validation/attestation ceremony.
type CredentialProof struct {
	ID               string
	AAGUID           string
	Platform         Platform
	SyncFabric       string
	BackupEligible   bool
	BackupState      bool
	UserVerified     bool
	WebAuthnVerified bool
	SignCount        uint32
}

func (p CredentialProof) Synced() bool {
	return p.BackupEligible && p.BackupState
}

// Device is one node in a user's Passkey device trust chain. ParentID is the
// device that authorized this device. Recovery devices intentionally get a
// new root instead of inheriting a lost parent's tainted chain; ReplacesID
// preserves audit lineage without extending trust ancestry.
type Device struct {
	ID            string
	TenantID      string
	UserID        string
	ParentID      string
	RootID        string
	ReplacesID    string
	Relation      Relation
	Status        DeviceStatus
	Platform      Platform
	SyncFabric    string
	Label         string
	CredentialIDs []string
	TrustedAt     time.Time
	LastSeenAt    time.Time
	ExpiresAt     *time.Time
	LostAt        *time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (d Device) Active(at time.Time) bool {
	if d.Status != DeviceStatusActive {
		return false
	}
	return d.ExpiresAt == nil || at.Before(*d.ExpiresAt)
}

func (d Device) hasCredential(credentialID string) bool {
	for _, id := range d.CredentialIDs {
		if id == credentialID {
			return true
		}
	}
	return false
}

// MigrationGrant is the stored, non-secret grant record. TokenHash contains
// SHA-256 of the one-time token returned exactly once to the caller.
type MigrationGrant struct {
	ID               string
	TenantID         string
	UserID           string
	SourceDeviceID   string
	TokenHash        string
	TargetPlatform   Platform
	TargetSyncFabric string
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
	ConsumedDeviceID string
	RevokedAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (g MigrationGrant) Pending(at time.Time) error {
	switch {
	case g.RevokedAt != nil:
		return ErrGrantRevoked
	case g.ConsumedAt != nil:
		return ErrGrantConsumed
	case !at.Before(g.ExpiresAt):
		return ErrGrantExpired
	default:
		return nil
	}
}

// SessionClaims contains optional device claims added to a normal Hanko JWT.
// An empty DeviceID represents a legacy session and remains accepted.
type SessionClaims struct {
	DeviceID   string
	Relation   Relation
	TrustLevel string
	Recovered  bool
}

// Store is the persistence boundary. Implementations must enforce tenant/user
// scoping and atomic one-time grant consumption in multi-instance deployments.
type Store interface {
	SaveDevice(ctx context.Context, device *Device) error
	GetDevice(ctx context.Context, tenantID, userID, deviceID string) (*Device, error)
	FindDeviceByCredential(ctx context.Context, tenantID, userID, credentialID string) (*Device, error)
	ListDevices(ctx context.Context, tenantID, userID string) ([]*Device, error)

	SaveGrant(ctx context.Context, grant *MigrationGrant) error
	GetGrantByTokenHash(ctx context.Context, tokenHash string) (*MigrationGrant, error)
	// ConsumeGrant must atomically reject expired/revoked/already-consumed grants.
	ConsumeGrant(ctx context.Context, tokenHash, consumedDeviceID string, at time.Time) (*MigrationGrant, error)
	RevokePendingGrantsFromDevice(ctx context.Context, tenantID, userID, deviceID string, at time.Time) error
}
