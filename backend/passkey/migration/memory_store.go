package migration

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore is a concurrency-safe Store used by acceptance tests, local
// development, and as a reference adapter. Production Hanko deployments should
// use the database adapter so multiple API instances share chain state.
type MemoryStore struct {
	mu      sync.RWMutex
	devices map[string]*Device
	grants  map[string]*MigrationGrant
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		devices: make(map[string]*Device),
		grants:  make(map[string]*MigrationGrant),
	}
}

func deviceKey(tenantID, userID, deviceID string) string {
	return tenantID + "\x00" + userID + "\x00" + deviceID
}

func (s *MemoryStore) SaveDevice(_ context.Context, device *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	copyDevice := cloneDevice(device)
	s.devices[deviceKey(copyDevice.TenantID, copyDevice.UserID, copyDevice.ID)] = copyDevice
	return nil
}

func (s *MemoryStore) GetDevice(_ context.Context, tenantID, userID, deviceID string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	device, ok := s.devices[deviceKey(tenantID, userID, deviceID)]
	if !ok {
		return nil, nil
	}
	return cloneDevice(device), nil
}

func (s *MemoryStore) FindDeviceByCredential(_ context.Context, tenantID, userID, credentialID string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []*Device
	for _, device := range s.devices {
		if device.TenantID != tenantID || device.UserID != userID {
			continue
		}
		if device.hasCredential(credentialID) {
			matches = append(matches, cloneDevice(device))
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	return matches[0], nil
}

func (s *MemoryStore) ListDevices(_ context.Context, tenantID, userID string) ([]*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var devices []*Device
	for _, device := range s.devices {
		if device.TenantID == tenantID && device.UserID == userID {
			devices = append(devices, cloneDevice(device))
		}
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].CreatedAt.Before(devices[j].CreatedAt)
	})
	return devices, nil
}

func (s *MemoryStore) SaveGrant(_ context.Context, grant *MigrationGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	copyGrant := cloneGrant(grant)
	s.grants[grant.TokenHash] = copyGrant
	return nil
}

func (s *MemoryStore) GetGrantByTokenHash(_ context.Context, tokenHash string) (*MigrationGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	grant, ok := s.grants[tokenHash]
	if !ok {
		return nil, nil
	}
	return cloneGrant(grant), nil
}

func (s *MemoryStore) ConsumeGrant(_ context.Context, tokenHash, consumedDeviceID string, at time.Time) (*MigrationGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	grant, ok := s.grants[tokenHash]
	if !ok {
		return nil, ErrGrantNotFound
	}
	if err := grant.Pending(at); err != nil {
		return nil, err
	}

	consumedAt := at
	grant.ConsumedAt = &consumedAt
	grant.ConsumedDeviceID = consumedDeviceID
	grant.UpdatedAt = at
	return cloneGrant(grant), nil
}

func (s *MemoryStore) RevokePendingGrantsFromDevice(_ context.Context, tenantID, userID, deviceID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, grant := range s.grants {
		if grant.TenantID != tenantID || grant.UserID != userID || grant.SourceDeviceID != deviceID {
			continue
		}
		if grant.ConsumedAt == nil && grant.RevokedAt == nil {
			revokedAt := at
			grant.RevokedAt = &revokedAt
			grant.UpdatedAt = at
		}
	}
	return nil
}

func cloneDevice(device *Device) *Device {
	if device == nil {
		return nil
	}
	copyValue := *device
	copyValue.CredentialIDs = append([]string{}, device.CredentialIDs...)
	if device.ExpiresAt != nil {
		expiresAt := *device.ExpiresAt
		copyValue.ExpiresAt = &expiresAt
	}
	if device.LostAt != nil {
		lostAt := *device.LostAt
		copyValue.LostAt = &lostAt
	}
	if device.RevokedAt != nil {
		revokedAt := *device.RevokedAt
		copyValue.RevokedAt = &revokedAt
	}
	return &copyValue
}

func cloneGrant(grant *MigrationGrant) *MigrationGrant {
	if grant == nil {
		return nil
	}
	copyValue := *grant
	if grant.ConsumedAt != nil {
		consumedAt := *grant.ConsumedAt
		copyValue.ConsumedAt = &consumedAt
	}
	if grant.RevokedAt != nil {
		revokedAt := *grant.RevokedAt
		copyValue.RevokedAt = &revokedAt
	}
	return &copyValue
}
