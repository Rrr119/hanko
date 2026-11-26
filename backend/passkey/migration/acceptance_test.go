package migration_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v3/config"
	"github.com/teamhanko/hanko/backend/v3/dto"
	"github.com/teamhanko/hanko/backend/v3/passkey/migration"
	"github.com/teamhanko/hanko/backend/v3/passkey/migrationsession"
	"github.com/teamhanko/hanko/backend/v3/session"
	"github.com/teamhanko/hanko/backend/v3/test"
)

const testUserID = "11111111-1111-4111-8111-111111111111"

func testService(t *testing.T) (*migration.Service, *migration.MemoryStore, time.Time) {
	t.Helper()

	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := migration.NewMemoryStore()
	service := migration.NewService(store, migration.Config{
		Clock:                   clock,
		MigrationTTL:            time.Minute,
		DeviceTrustTTL:          time.Hour,
		RequireUserVerification: true,
	})
	return service, store, now
}

func TestMigrationGrantConcurrentConsumption(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t)
	tenantID := testTenantID(t).String()

	source, err := service.EnrollRoot(ctx, migration.EnrollRootInput{
		TenantID:   tenantID,
		UserID:     testUserID,
		DeviceID:   "device-source-concurrent",
		Credential: syncedProof("credential-source-concurrent"),
	})
	require.NoError(t, err)

	grant, err := service.CreateMigrationGrant(ctx, migration.CreateGrantInput{
		TenantID:       tenantID,
		UserID:         testUserID,
		SourceDeviceID: source.ID,
	})
	require.NoError(t, err)

	const attempts = 16
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	wg.Add(attempts)
	for attempt := 0; attempt < attempts; attempt++ {
		attempt := attempt
		go func() {
			defer wg.Done()
			_, _, err := service.AcceptMigration(ctx, migration.AcceptMigrationInput{
				Token:       grant.Token,
				NewDeviceID: fmt.Sprintf("device-concurrent-%d", attempt),
				Credential:  syncedProof(fmt.Sprintf("credential-concurrent-%d", attempt)),
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	consumedErrors := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, migration.ErrGrantConsumed):
			consumedErrors++
		default:
			require.NoError(t, err)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, attempts-1, consumedErrors)
}

func testTenantID(t *testing.T) uuid.UUID {
	t.Helper()
	return uuid.FromStringOrNil(config.DefaultTenantID)
}

func syncedProof(credentialID string) migration.CredentialProof {
	return migration.CredentialProof{
		ID:               credentialID,
		Platform:         migration.PlatformApple,
		SyncFabric:       "icloud-keychain",
		BackupEligible:   true,
		BackupState:      true,
		UserVerified:     true,
		WebAuthnVerified: true,
	}
}

func assertSessionCompatible(t *testing.T, service *migration.Service, device *migration.Device, recovered bool) {
	t.Helper()

	tenantID := testTenantID(t)
	manager, err := session.NewManager(test.JwkManager{}, config.TenantConfig{
		Session: config.Session{Lifespan: "5m"},
	})
	require.NoError(t, err)

	claims := migration.SessionClaims{
		DeviceID:   device.ID,
		Relation:   device.Relation,
		TrustLevel: "passkey",
		Recovered:  recovered,
	}
	tokenString, rawToken, cookie, err := migrationsession.Issue(manager, dto.UserJWT{UserID: testUserID}, tenantID, claims)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)
	require.NotNil(t, cookie)

	verified, err := manager.Verify(tokenString, tenantID)
	require.NoError(t, err)

	deviceClaims := migration.SessionClaimsFromToken(verified)
	assert.Equal(t, device.ID, deviceClaims.DeviceID)
	assert.Equal(t, device.Relation, deviceClaims.Relation)
	assert.Equal(t, recovered, deviceClaims.Recovered)

	require.NoError(t, service.AuthorizeSession(context.Background(), tenantID.String(), testUserID, deviceClaims))

	// The same manager still accepts a session issued without device claims.
	legacyToken, _, err := manager.GenerateJWT(dto.UserJWT{UserID: testUserID}, tenantID)
	require.NoError(t, err)
	legacyVerified, err := manager.Verify(legacyToken, tenantID)
	require.NoError(t, err)
	legacyClaims := migration.SessionClaimsFromToken(legacyVerified)
	assert.Empty(t, legacyClaims.DeviceID)
	require.NoError(t, service.AuthorizeSession(context.Background(), tenantID.String(), testUserID, legacyClaims))

	// Raw token is returned for callers that need Hanko's existing claims DTO.
	assert.NotNil(t, rawToken)
}

func TestAcceptance_SamePlatformSync(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t)
	tenantID := testTenantID(t).String()

	original, err := service.EnrollRoot(ctx, migration.EnrollRootInput{
		TenantID:   tenantID,
		UserID:     testUserID,
		DeviceID:   "device-iphone-old",
		Label:      "Old iPhone",
		Platform:   migration.PlatformApple,
		SyncFabric: "icloud-keychain",
		Credential: syncedProof("credential-synced-passkey"),
	})
	require.NoError(t, err)

	newPhone, err := service.SyncToDevice(ctx, migration.SyncInput{
		TenantID:       tenantID,
		UserID:         testUserID,
		AnchorDeviceID: original.ID,
		NewDeviceID:    "device-iphone-new",
		Label:          "New iPhone",
		Platform:       migration.PlatformApple,
		SyncFabric:     "icloud-keychain",
		Credential:     syncedProof("credential-synced-passkey"),
	})
	require.NoError(t, err)

	assert.Equal(t, migration.RelationSamePlatformSync, newPhone.Relation)
	assert.Equal(t, original.ID, newPhone.ParentID)
	assert.Equal(t, original.RootID, newPhone.RootID)
	assert.Equal(t, migration.DeviceStatusActive, newPhone.Status)
	assert.Contains(t, newPhone.CredentialIDs, "credential-synced-passkey")
	require.NoError(t, service.AuthorizeSession(ctx, tenantID, testUserID, migration.SessionClaims{DeviceID: newPhone.ID}))

	assertSessionCompatible(t, service, newPhone, false)
}

func TestAcceptance_CrossPlatformMigration(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t)
	tenantID := testTenantID(t).String()

	android, err := service.EnrollRoot(ctx, migration.EnrollRootInput{
		TenantID: tenantID,
		UserID:   testUserID,
		DeviceID: "device-android",
		Platform: migration.PlatformGoogle,
		Credential: migration.CredentialProof{
			ID:               "credential-android-passkey",
			Platform:         migration.PlatformGoogle,
			BackupEligible:   true,
			BackupState:      true,
			UserVerified:     true,
			WebAuthnVerified: true,
		},
	})
	require.NoError(t, err)

	// An unknown Apple device cannot simply claim the Google sync fabric.
	_, err = service.SyncToDevice(ctx, migration.SyncInput{
		TenantID:    tenantID,
		UserID:      testUserID,
		NewDeviceID: "device-iphone-unapproved",
		Platform:    migration.PlatformApple,
		Credential:  syncedProof("credential-android-passkey"),
	})
	require.ErrorIs(t, err, migration.ErrCrossPlatformGrantRequired)

	grant, err := service.CreateMigrationGrant(ctx, migration.CreateGrantInput{
		TenantID:       tenantID,
		UserID:         testUserID,
		SourceDeviceID: android.ID,
		TargetPlatform: migration.PlatformApple,
		TargetFabric:   "icloud-keychain",
	})
	require.NoError(t, err)
	require.Contains(t, grant.Token, "hkt_")

	target, consumedGrant, err := service.AcceptMigration(ctx, migration.AcceptMigrationInput{
		Token:       grant.Token,
		NewDeviceID: "device-iphone-migrated",
		Label:       "Migrated iPhone",
		Credential: migration.CredentialProof{
			ID:               "credential-iphone-passkey",
			Platform:         migration.PlatformApple,
			SyncFabric:       "icloud-keychain",
			BackupEligible:   true,
			BackupState:      true,
			UserVerified:     true,
			WebAuthnVerified: true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, consumedGrant.ConsumedAt)
	assert.Equal(t, migration.RelationCrossPlatformMigration, target.Relation)
	assert.Equal(t, android.ID, target.ParentID)
	assert.Equal(t, android.RootID, target.RootID)

	_, _, err = service.AcceptMigration(ctx, migration.AcceptMigrationInput{
		Token:       grant.Token,
		NewDeviceID: "device-replay",
		Credential:  syncedProof("credential-replay"),
	})
	require.ErrorIs(t, err, migration.ErrGrantConsumed)

	require.NoError(t, service.AuthorizeSession(ctx, tenantID, testUserID, migration.SessionClaims{DeviceID: target.ID}))
	assertSessionCompatible(t, service, target, false)
}

func TestAcceptance_DeviceLossRecoveryAndRejection(t *testing.T) {
	ctx := context.Background()
	tenantID := testTenantID(t).String()

	t.Run("synced passkey recovers replacement device", func(t *testing.T) {
		service, store, _ := testService(t)

		lostPhone, err := service.EnrollRoot(ctx, migration.EnrollRootInput{
			TenantID:   tenantID,
			UserID:     testUserID,
			DeviceID:   "device-lost",
			Platform:   migration.PlatformApple,
			SyncFabric: "icloud-keychain",
			Credential: syncedProof("credential-available-in-cloud"),
		})
		require.NoError(t, err)

		_, err = service.ReportLost(ctx, tenantID, testUserID, lostPhone.ID)
		require.NoError(t, err)

		err = service.AuthorizeSession(ctx, tenantID, testUserID, migration.SessionClaims{DeviceID: lostPhone.ID})
		require.ErrorIs(t, err, migration.ErrDeviceLost)

		_, err = service.CreateMigrationGrant(ctx, migration.CreateGrantInput{
			TenantID:       tenantID,
			UserID:         testUserID,
			SourceDeviceID: lostPhone.ID,
		})
		require.ErrorIs(t, err, migration.ErrDeviceLost)

		replacement, err := service.RecoverWithSyncedPasskey(ctx, migration.RecoveryInput{
			TenantID:    tenantID,
			UserID:      testUserID,
			NewDeviceID: "device-replacement",
			Platform:    migration.PlatformApple,
			SyncFabric:  "icloud-keychain",
			Credential:  syncedProof("credential-available-in-cloud"),
		})
		require.NoError(t, err)
		assert.Equal(t, migration.RelationRecovery, replacement.Relation)
		assert.Empty(t, replacement.ParentID, "recovery gets a fresh root so the lost device cannot taint the new chain")
		assert.Equal(t, lostPhone.ID, replacement.ReplacesID)

		require.NoError(t, service.AuthorizeSession(ctx, tenantID, testUserID, migration.SessionClaims{DeviceID: replacement.ID}))
		assertSessionCompatible(t, service, replacement, true)

		devices, err := store.ListDevices(ctx, tenantID, testUserID)
		require.NoError(t, err)
		require.Len(t, devices, 2)
	})

	t.Run("device bound passkey is safely rejected", func(t *testing.T) {
		service, store, _ := testService(t)

		deviceBound, err := service.EnrollRoot(ctx, migration.EnrollRootInput{
			TenantID: tenantID,
			UserID:   testUserID,
			DeviceID: "device-bound",
			Credential: migration.CredentialProof{
				ID:               "credential-device-bound",
				BackupEligible:   false,
				BackupState:      false,
				UserVerified:     true,
				WebAuthnVerified: true,
			},
		})
		require.NoError(t, err)

		_, err = service.ReportLost(ctx, tenantID, testUserID, deviceBound.ID)
		require.NoError(t, err)

		_, err = service.RecoverWithSyncedPasskey(ctx, migration.RecoveryInput{
			TenantID:   tenantID,
			UserID:     testUserID,
			Credential: migration.CredentialProof{ID: "credential-device-bound", BackupEligible: false, BackupState: false, UserVerified: true, WebAuthnVerified: true},
		})
		require.ErrorIs(t, err, migration.ErrRecoveryUnavailable)

		err = service.AuthorizeSession(ctx, tenantID, testUserID, migration.SessionClaims{DeviceID: deviceBound.ID})
		require.ErrorIs(t, err, migration.ErrDeviceLost)

		devices, err := store.ListDevices(ctx, tenantID, testUserID)
		require.NoError(t, err)
		require.Len(t, devices, 1, "failed recovery must not create a usable device")
	})

	t.Run("lost source revokes pending cross-platform grant and descendants", func(t *testing.T) {
		service, _, _ := testService(t)

		source, err := service.EnrollRoot(ctx, migration.EnrollRootInput{
			TenantID:   tenantID,
			UserID:     testUserID,
			DeviceID:   "device-source",
			Credential: syncedProof("credential-source"),
		})
		require.NoError(t, err)

		syncedChild, err := service.SyncToDevice(ctx, migration.SyncInput{
			TenantID:       tenantID,
			UserID:         testUserID,
			AnchorDeviceID: source.ID,
			NewDeviceID:    "device-child",
			Credential:     syncedProof("credential-source"),
		})
		require.NoError(t, err)

		grant, err := service.CreateMigrationGrant(ctx, migration.CreateGrantInput{
			TenantID:       tenantID,
			UserID:         testUserID,
			SourceDeviceID: source.ID,
		})
		require.NoError(t, err)

		_, err = service.ReportLost(ctx, tenantID, testUserID, source.ID)
		require.NoError(t, err)

		_, _, err = service.AcceptMigration(ctx, migration.AcceptMigrationInput{
			Token:       grant.Token,
			NewDeviceID: "device-should-not-exist",
			Credential:  syncedProof("credential-new"),
		})
		require.ErrorIs(t, err, migration.ErrGrantRevoked)

		err = service.AuthorizeSession(ctx, tenantID, testUserID, migration.SessionClaims{DeviceID: syncedChild.ID})
		require.Error(t, err)
		assert.True(t, errors.Is(err, migration.ErrBrokenTrustChain) || errors.Is(err, migration.ErrDeviceLost))
	})
}
