package migration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
)

const (
	DefaultMigrationTTL   = 15 * time.Minute
	DefaultDeviceTrustTTL = 30 * 24 * time.Hour
)

type Clock func() time.Time

type IDGenerator func() string

type Config struct {
	Clock                   Clock
	NewID                   IDGenerator
	MigrationTTL            time.Duration
	DeviceTrustTTL          time.Duration
	RequireUserVerification bool
}

type Service struct {
	store Store
	cfg   Config
}

func NewService(store Store, cfg Config) *Service {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.NewID == nil {
		cfg.NewID = func() string {
			return uuid.Must(uuid.NewV4()).String()
		}
	}
	if cfg.MigrationTTL <= 0 {
		cfg.MigrationTTL = DefaultMigrationTTL
	}
	if cfg.DeviceTrustTTL == 0 {
		cfg.DeviceTrustTTL = DefaultDeviceTrustTTL
	}
	return &Service{store: store, cfg: cfg}
}

func (s *Service) now() time.Time {
	return s.cfg.Clock().UTC()
}

func (s *Service) newID() string {
	return s.cfg.NewID()
}

// EnrollRoot records the first device trusted for a fully verified Passkey.
func (s *Service) EnrollRoot(ctx context.Context, in EnrollRootInput) (*Device, error) {
	if err := validatePrincipal(in.TenantID, in.UserID); err != nil {
		return nil, err
	}
	if err := s.verifyProof(in.Credential); err != nil {
		return nil, err
	}

	now := s.now()
	deviceID := orDefault(in.DeviceID, s.newID())
	device := &Device{
		ID:            deviceID,
		TenantID:      in.TenantID,
		UserID:        in.UserID,
		RootID:        deviceID,
		Relation:      RelationRoot,
		Status:        DeviceStatusActive,
		Platform:      orDefaultPlatform(in.Platform, in.Credential.Platform),
		SyncFabric:    orDefaultString(in.SyncFabric, in.Credential.SyncFabric),
		Label:         in.Label,
		CredentialIDs: []string{in.Credential.ID},
		TrustedAt:     now,
		LastSeenAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if in.Legacy {
		device.Relation = RelationLegacyRoot
	}
	if s.cfg.DeviceTrustTTL > 0 {
		expiresAt := now.Add(s.cfg.DeviceTrustTTL)
		device.ExpiresAt = &expiresAt
	}

	if err := s.store.SaveDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("save root passkey device: %w", err)
	}
	return device, nil
}

type EnrollRootInput struct {
	TenantID   string
	UserID     string
	DeviceID   string
	Label      string
	Platform   Platform
	SyncFabric string
	Credential CredentialProof
	Legacy     bool
}

type SyncInput struct {
	TenantID       string
	UserID         string
	AnchorDeviceID string
	NewDeviceID    string
	Label          string
	Platform       Platform
	SyncFabric     string
	Credential     CredentialProof
}

// SyncToDevice records a new device using a passkey synchronized through the
// same platform/fabric as an already trusted anchor.
func (s *Service) SyncToDevice(ctx context.Context, in SyncInput) (*Device, error) {
	if err := validatePrincipal(in.TenantID, in.UserID); err != nil {
		return nil, err
	}
	if err := s.verifyProof(in.Credential); err != nil {
		return nil, err
	}
	if !in.Credential.Synced() {
		return nil, ErrBackupNotAvailable
	}

	anchor, err := s.findAnchor(ctx, in.TenantID, in.UserID, in.AnchorDeviceID, in.Credential.ID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if anchor.Status == DeviceStatusActive {
		anchor.LastSeenAt = now
		if s.cfg.DeviceTrustTTL > 0 {
			expiresAt := now.Add(s.cfg.DeviceTrustTTL)
			anchor.ExpiresAt = &expiresAt
		}
		if err := s.store.SaveDevice(ctx, anchor); err != nil {
			return nil, fmt.Errorf("touch synced passkey anchor: %w", err)
		}
	}
	if err := s.authorizeDevice(ctx, anchor); err != nil {
		return nil, err
	}
	if !sameSyncFabric(anchor, in.Platform, in.SyncFabric, in.Credential) {
		return nil, ErrCrossPlatformGrantRequired
	}

	deviceID := orDefault(in.NewDeviceID, s.newID())
	device := s.childDevice(anchor, deviceID, in.Label, in.Platform, in.SyncFabric, in.Credential, RelationSamePlatformSync, now)
	if err := s.store.SaveDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("save synced passkey device: %w", err)
	}
	return device, nil
}

type CreateGrantInput struct {
	TenantID       string
	UserID         string
	SourceDeviceID string
	TargetPlatform Platform
	TargetFabric   string
	TTL            time.Duration
}

type CreatedGrant struct {
	Grant MigrationGrant
	Token string
}

// CreateMigrationGrant creates a short-lived one-time approval from a trusted
// source device for a cross-platform target.
func (s *Service) CreateMigrationGrant(ctx context.Context, in CreateGrantInput) (*CreatedGrant, error) {
	if err := validatePrincipal(in.TenantID, in.UserID); err != nil {
		return nil, err
	}
	if in.SourceDeviceID == "" {
		return nil, fmt.Errorf("%w: source_device_id is required", ErrInvalidInput)
	}

	source, err := s.store.GetDevice(ctx, in.TenantID, in.UserID, in.SourceDeviceID)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, ErrDeviceNotFound
	}
	if err := s.authorizeDevice(ctx, source); err != nil {
		return nil, err
	}

	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.cfg.MigrationTTL
	}
	now := s.now()
	grant := MigrationGrant{
		ID:               s.newID(),
		TenantID:         in.TenantID,
		UserID:           in.UserID,
		SourceDeviceID:   source.ID,
		TokenHash:        HashToken(token),
		TargetPlatform:   in.TargetPlatform,
		TargetSyncFabric: in.TargetFabric,
		ExpiresAt:        now.Add(ttl),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.store.SaveGrant(ctx, &grant); err != nil {
		return nil, fmt.Errorf("save passkey migration grant: %w", err)
	}
	return &CreatedGrant{Grant: grant, Token: token}, nil
}

type AcceptMigrationInput struct {
	Token       string
	NewDeviceID string
	Label       string
	Credential  CredentialProof
}

// AcceptMigration consumes a one-time grant and links the target device to the
// approving source device. The target CredentialProof must come from a verified
// WebAuthn registration/assertion on the target platform.
func (s *Service) AcceptMigration(ctx context.Context, in AcceptMigrationInput) (*Device, *MigrationGrant, error) {
	if in.Token == "" {
		return nil, nil, fmt.Errorf("%w: token is required", ErrInvalidInput)
	}
	if err := s.verifyProof(in.Credential); err != nil {
		return nil, nil, err
	}

	tokenHash := HashToken(in.Token)
	grant, err := s.store.GetGrantByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, err
	}
	if grant == nil {
		return nil, nil, ErrGrantNotFound
	}
	now := s.now()
	if err := grant.Pending(now); err != nil {
		return nil, nil, err
	}

	source, err := s.store.GetDevice(ctx, grant.TenantID, grant.UserID, grant.SourceDeviceID)
	if err != nil {
		return nil, nil, err
	}
	if source == nil {
		return nil, nil, ErrDeviceNotFound
	}
	if err := s.authorizeDevice(ctx, source); err != nil {
		return nil, nil, err
	}

	deviceID := orDefault(in.NewDeviceID, s.newID())
	platform := orDefaultPlatform(in.Credential.Platform, grant.TargetPlatform)
	fabric := orDefaultString(in.Credential.SyncFabric, grant.TargetSyncFabric)
	device := s.childDevice(source, deviceID, in.Label, platform, fabric, in.Credential, RelationCrossPlatformMigration, now)

	// Atomically consume the grant before creating the linked device so two
	// concurrent/replayed ceremonies cannot both succeed.
	consumedGrant, err := s.store.ConsumeGrant(ctx, grant.TokenHash, device.ID, now)
	if err != nil {
		return nil, nil, fmt.Errorf("consume passkey migration grant: %w", err)
	}
	if err := s.store.SaveDevice(ctx, device); err != nil {
		return nil, nil, fmt.Errorf("save migrated passkey device: %w", err)
	}

	return device, consumedGrant, nil
}

type RecoveryInput struct {
	TenantID    string
	UserID      string
	NewDeviceID string
	Label       string
	Platform    Platform
	SyncFabric  string
	Credential  CredentialProof
}

// RecoverWithSyncedPasskey establishes a new trust root after device loss. A
// healthy BE=1/BS=1 credential plus a valid assertion is the recovery factor.
// Device-bound or currently unsynchronized credentials are rejected.
func (s *Service) RecoverWithSyncedPasskey(ctx context.Context, in RecoveryInput) (*Device, error) {
	if err := validatePrincipal(in.TenantID, in.UserID); err != nil {
		return nil, err
	}
	if err := s.verifyProof(in.Credential); err != nil {
		return nil, err
	}
	if !in.Credential.Synced() {
		return nil, fmt.Errorf("%w: backup_eligible=%t backup_state=%t", ErrRecoveryUnavailable, in.Credential.BackupEligible, in.Credential.BackupState)
	}

	previous, err := s.store.FindDeviceByCredential(ctx, in.TenantID, in.UserID, in.Credential.ID)
	if err != nil {
		return nil, err
	}

	now := s.now()
	deviceID := orDefault(in.NewDeviceID, s.newID())
	device := &Device{
		ID:            deviceID,
		TenantID:      in.TenantID,
		UserID:        in.UserID,
		RootID:        deviceID,
		ReplacesID:    deviceIDOrEmpty(previous),
		Relation:      RelationRecovery,
		Status:        DeviceStatusActive,
		Platform:      orDefaultPlatform(in.Platform, in.Credential.Platform),
		SyncFabric:    orDefaultString(in.SyncFabric, in.Credential.SyncFabric),
		Label:         in.Label,
		CredentialIDs: []string{in.Credential.ID},
		TrustedAt:     now,
		LastSeenAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if s.cfg.DeviceTrustTTL > 0 {
		expiresAt := now.Add(s.cfg.DeviceTrustTTL)
		device.ExpiresAt = &expiresAt
	}
	if err := s.store.SaveDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("save recovered passkey device: %w", err)
	}
	return device, nil
}

// ReportLost marks a device lost and revokes migration grants it issued.
// Strict chain verification also rejects descendants until they recover.
func (s *Service) ReportLost(ctx context.Context, tenantID, userID, deviceID string) (*Device, error) {
	if err := validatePrincipal(tenantID, userID); err != nil {
		return nil, err
	}
	if deviceID == "" {
		return nil, fmt.Errorf("%w: device_id is required", ErrInvalidInput)
	}

	device, err := s.store.GetDevice(ctx, tenantID, userID, deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrDeviceNotFound
	}

	now := s.now()
	if device.Status != DeviceStatusLost {
		device.Status = DeviceStatusLost
		device.LostAt = &now
		device.UpdatedAt = now
		if err := s.store.SaveDevice(ctx, device); err != nil {
			return nil, fmt.Errorf("mark passkey device lost: %w", err)
		}
	}
	if err := s.store.RevokePendingGrantsFromDevice(ctx, tenantID, userID, deviceID, now); err != nil {
		return nil, fmt.Errorf("revoke migration grants for lost device: %w", err)
	}
	return device, nil
}

// AuthorizeSession enforces current device status/lineage for sessions that
// contain a did claim. Sessions without did are legacy sessions and are allowed
// through unchanged; ordinary JWT signature/expiry/revocation checks still run.
func (s *Service) AuthorizeSession(ctx context.Context, tenantID, userID string, claims SessionClaims) error {
	if claims.DeviceID == "" {
		return nil
	}
	if err := validatePrincipal(tenantID, userID); err != nil {
		return err
	}
	device, err := s.store.GetDevice(ctx, tenantID, userID, claims.DeviceID)
	if err != nil {
		return err
	}
	if device == nil {
		return ErrDeviceNotFound
	}
	return s.authorizeDevice(ctx, device)
}

func (s *Service) verifyProof(proof CredentialProof) error {
	if proof.ID == "" {
		return fmt.Errorf("%w: credential id is required", ErrInvalidInput)
	}
	if !proof.WebAuthnVerified {
		return ErrWebAuthnNotVerified
	}
	if s.cfg.RequireUserVerification && !proof.UserVerified {
		return ErrUserVerificationRequired
	}
	return nil
}

func (s *Service) findAnchor(ctx context.Context, tenantID, userID, deviceID, credentialID string) (*Device, error) {
	if deviceID != "" {
		device, err := s.store.GetDevice(ctx, tenantID, userID, deviceID)
		if err != nil {
			return nil, err
		}
		if device == nil {
			return nil, ErrDeviceNotFound
		}
		if !device.hasCredential(credentialID) {
			byCredential, err := s.store.FindDeviceByCredential(ctx, tenantID, userID, credentialID)
			if err != nil {
				return nil, err
			}
			if byCredential == nil {
				return nil, fmt.Errorf("%w: credential is not linked to device", ErrUntrustedDevice)
			}
			return byCredential, nil
		}
		return device, nil
	}

	device, err := s.store.FindDeviceByCredential(ctx, tenantID, userID, credentialID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrDeviceNotFound
	}
	return device, nil
}

func (s *Service) authorizeDevice(ctx context.Context, device *Device) error {
	if device == nil {
		return ErrDeviceNotFound
	}
	now := s.now()
	switch device.Status {
	case DeviceStatusLost:
		return ErrDeviceLost
	case DeviceStatusRevoked:
		return ErrDeviceRevoked
	case DeviceStatusActive:
		if device.ExpiresAt != nil && !now.Before(*device.ExpiresAt) {
			return ErrDeviceExpired
		}
	default:
		return ErrDeviceInactive
	}

	visited := map[string]struct{}{device.ID: {}}
	current := device
	for current.ParentID != "" {
		if _, seen := visited[current.ParentID]; seen {
			return fmt.Errorf("%w: cycle at %s", ErrBrokenTrustChain, current.ParentID)
		}
		visited[current.ParentID] = struct{}{}

		parent, err := s.store.GetDevice(ctx, device.TenantID, device.UserID, current.ParentID)
		if err != nil {
			return err
		}
		if parent == nil {
			return fmt.Errorf("%w: missing parent %s", ErrBrokenTrustChain, current.ParentID)
		}
		if parent.TenantID != device.TenantID || parent.UserID != device.UserID {
			return ErrTrustChainOwnerMismatch
		}
		if !parent.Active(now) {
			if parent.Status == DeviceStatusLost {
				return fmt.Errorf("%w: parent %s: %w", ErrBrokenTrustChain, parent.ID, ErrDeviceLost)
			}
			if parent.Status == DeviceStatusRevoked {
				return fmt.Errorf("%w: parent %s: %w", ErrBrokenTrustChain, parent.ID, ErrDeviceRevoked)
			}
			return fmt.Errorf("%w: parent %s is inactive", ErrBrokenTrustChain, parent.ID)
		}
		current = parent
	}
	if current.Relation != RelationRoot && current.Relation != RelationLegacyRoot && current.Relation != RelationRecovery {
		return fmt.Errorf("%w: chain does not end in a root/recovery node", ErrBrokenTrustChain)
	}
	return nil
}

func (s *Service) childDevice(parent *Device, id, label string, platform Platform, fabric string, proof CredentialProof, relation Relation, now time.Time) *Device {
	credentialIDs := append([]string{}, parent.CredentialIDs...)
	if relation == RelationCrossPlatformMigration {
		credentialIDs = []string{}
	}
	if proof.ID != "" {
		credentialIDs = appendUnique(credentialIDs, proof.ID)
	}
	device := &Device{
		ID:            id,
		TenantID:      parent.TenantID,
		UserID:        parent.UserID,
		ParentID:      parent.ID,
		RootID:        parent.RootID,
		Relation:      relation,
		Status:        DeviceStatusActive,
		Platform:      orDefaultPlatform(platform, proof.Platform, parent.Platform),
		SyncFabric:    orDefaultString(fabric, proof.SyncFabric, parent.SyncFabric),
		Label:         label,
		CredentialIDs: credentialIDs,
		TrustedAt:     now,
		LastSeenAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if s.cfg.DeviceTrustTTL > 0 {
		expiresAt := now.Add(s.cfg.DeviceTrustTTL)
		device.ExpiresAt = &expiresAt
	}
	return device
}

func validatePrincipal(tenantID, userID string) error {
	if tenantID == "" || userID == "" {
		return fmt.Errorf("%w: tenant_id and user_id are required", ErrInvalidInput)
	}
	return nil
}

func sameSyncFabric(anchor *Device, platform Platform, fabric string, proof CredentialProof) bool {
	candidateFabric := orDefaultString(fabric, proof.SyncFabric)
	if candidateFabric != "" && anchor.SyncFabric != "" {
		return candidateFabric == anchor.SyncFabric
	}
	candidatePlatform := orDefaultPlatform(platform, proof.Platform)
	return candidatePlatform != "" && anchor.Platform != "" && candidatePlatform == anchor.Platform
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate migration token: %w", err)
	}
	return "hkt_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func orDefault[T comparable](value, fallback T) T {
	var zero T
	if value != zero {
		return value
	}
	return fallback
}

func orDefaultString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func orDefaultPlatform(values ...Platform) Platform {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func deviceIDOrEmpty(device *Device) string {
	if device == nil {
		return ""
	}
	return device.ID
}
