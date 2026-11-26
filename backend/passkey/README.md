# Passkey multi-device trust and migration

Passkey private keys normally remain inside the platform authenticator or its
encrypted sync fabric. Hanko cannot and should not export them. Cross-device
availability comes from one of two mechanisms:

1. **Same-platform sync** — Apple Keychain, Google Password Manager and similar
   fabrics synchronize a backup-eligible (`BE=1`) and currently backed-up
   (`BS=1`) credential. The new device presents the same credential and a valid
   assertion.
2. **Cross-platform transfer/hybrid use** — the platforms perform QR/hybrid
   proximity or an encrypted transfer. Hanko additionally binds the resulting
   device to a one-time migration grant approved by an already trusted device.

This directory contains the policy core for those decisions. It is storage
agnostic; `persistence.PasskeyMigrationStore` provides the Pop adapter and the
`20261126130000_create_passkey_device_trust` migration creates its tables.

## Trust chain

Each `migration.Device` records:

- a root, recovery root, or parent device;
- the relationship: `root`, `legacy_root`, `same_platform_sync`,
  `cross_platform_migration`, or `recovery`;
- status: `active`, `lost`, or `revoked`;
- platform/sync fabric and linked WebAuthn credential IDs.

A lost device is rejected by `AuthorizeSession`. Strict chain verification also
rejects devices whose parent was lost or revoked. A healthy synced Passkey can
then establish a fresh `recovery` root; device-bound or currently unsynchronized
credentials receive `ErrRecoveryUnavailable`.

## Session compatibility

Recovery and migration do not create a second session format.
`passkey/migrationsession.Issue` calls the existing `session.Manager` and only
adds optional claims:

- `did`: Passkey device-chain ID;
- `drel`: trust relationship;
- `trust_level`: currently `passkey`;
- `passkey_recovered`: true for recovery roots.

Ordinary JWT signature, audience/issuer, expiry and server-side session checks
remain unchanged. Tokens without `did` are legacy sessions and continue to
work. `middleware.PasskeyDeviceSession` performs the optional current-status
check when `did` is present, and `/sessions/validate` returns `is_valid:false`
for a `did` whose device was lost, revoked, expired, or removed from a valid
trust chain.

## HTTP flow

All endpoints are tenant scoped.

1. Sign in on the new device with the normal Hanko login flow and the synced or
   hybrid-transferred Passkey, so the session contains AMR `passkey`.
2. Register/bind the current device:

   ```http
   POST /passkey/devices/current
   Authorization: Bearer <session-jwt>
   Content-Type: application/json

   {
     "credential_id": "<webauthn credential id>",
     "device_id": "<stable client-generated uuid>",
     "platform": "apple",
     "sync_fabric": "icloud-keychain"
   }
   ```

   If the credential was previously bound to a lost device, the same call
   performs the synced recovery and returns a new session cookie/token with
   `passkey_recovered=true`.
3. For cross-platform migration, create a short-lived grant on an existing
   trusted device:

   ```http
   POST /passkey/migration-grants
   Authorization: Bearer <source-session-jwt>

   { "source_device_id": "<source device>", "target_platform": "apple" }
   ```

   The `token` in the `201` response is shown once. Include it as
   `migration_token` in step 2 on the target. Grants are one-time and are
   revoked when the source device is reported lost.
4. List or revoke devices:

   ```http
   GET  /passkey/devices
   POST /passkey/devices/:device_id/lost
   ```

The HTTP layer intentionally trusts `backup_eligible` and `backup_state` only
from Hanko's stored WebAuthn credential record. `WebAuthnVerified` is implied
by a current session with the server-determined `passkey` AMR. New direct
integrations should call `migration.Service` immediately after a successful
go-webauthn ceremony and set `CredentialProof.WebAuthnVerified=true` there.

## Acceptance tests

`backend/passkey/migration/acceptance_test.go` covers:

- same-platform sync creates an active child device and compatible session;
- cross-platform migration requires and consumes a one-time grant, rejects
  replay, and links parent/child;
- device loss rejects the lost session and pending grants, allows healthy
  synced-Passkey recovery, and safely rejects device-bound credentials.

Run:

```sh
cd backend
go test -short ./passkey/migration -run TestAcceptance -v
```
