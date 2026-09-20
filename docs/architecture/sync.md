# Opaque Sync and Household Key Distribution

Status: target protocol architecture; not implemented end-to-end. The existing
`apps/api` opaque object endpoints are an initial transport surface.
`crates/vault-sync` now implements the bounded versioned account/household/
membership/space domain contracts and a ciphertext-preserving single-owner
migration plan. It also prepares and opens device-specific, generation-bound
space-key envelopes; atomic server rotation fencing, mutation/pull protocol,
and client persistence remain incomplete.

## Goals

- converge authorized web and extension clients without server plaintext;
- support accounts, households, private/shared spaces, attachments, history,
  reminders, collaboration, and Trust Engine objects;
- preserve offline operation and reject silent stale overwrites;
- revoke devices/members from future access and rotate affected key envelopes;
- remain bounded and compatible across supported client versions.

## Non-goals

- server-side merging of encrypted records;
- server interpretation of item kinds, titles, tombstone meaning, reminder
  content, or household names;
- recall of plaintext already read by a formerly authorized device;
- using last-writer-wins to hide genuine concurrent edits;
- treating Cognito sessions as decryption authority.

## Actors and identifiers

```text
AccountId      hosted sign-in/subscription boundary
HouseholdId    collaboration boundary
MembershipId   account <-> household role assignment
DeviceId       revocable sync and cryptographic device identity
SpaceId        private/shared/purpose key boundary
ObjectId       opaque synchronized object identity
OperationId    idempotency identity for one mutation
Cursor         account/household change-feed position
```

Identifiers are random and opaque. Human-readable names, relationship labels,
item categories, and content remain encrypted.

## Authorization layers

Every request must pass all applicable layers:

1. hosted account authentication;
2. active Safeory device credential;
3. account/household/space server authorization for the operation;
4. valid object revision/idempotency preconditions;
5. client possession of the required space/item key before content is readable.

The server can deny an operation but cannot make unauthorized ciphertext
readable. A client with a key but a revoked device credential cannot fetch new
objects or envelopes.

## Object classes

The change feed treats bodies as ciphertext but distinguishes bounded routing
classes:

- account/device bootstrap metadata;
- encrypted household profile;
- encrypted space manifest;
- encrypted space-key envelope per authorized device;
- encrypted item/tombstone;
- encrypted attachment manifest and chunks;
- encrypted item history;
- encrypted reminder/activity/Inbox objects;
- encrypted SecureLink copy;
- encrypted recovery/emergency capsule;
- minimal server-visible security/workflow event.

Each opaque object has an account and, where applicable, household/space scope;
object ID; class; monotonically increasing safe-integer revision; ciphertext
size/hash; created/updated timestamps required for sync; and tombstone state.
The API never accepts a caller-supplied account scope independent of the
authenticated device.

## Device and account bootstrap

### First device

1. Create/verify the hosted account.
2. Generate the Account Secret/device cryptographic identities on the client.
3. Create the AccountRootKey and initial private household/space locally.
4. Upload only public device registration, encrypted root/space envelopes, and
   opaque ciphertext objects.
5. Return one-time device authorization material only once; persist only its
   verifier/hash server-side.

The exact Account Secret construction and root-wrap migration require a crypto
ADR before implementation.

### Additional device

1. The new device authenticates the hosted account but has no content key.
2. An active device or reviewed recovery path authorizes enrollment.
3. The new device proves possession of its encryption/signing keys.
4. An authorized client wraps only the required account/space keys to that
   device.
5. The service activates the device and records a minimal security event.

Email or Cognito access alone cannot deliver usable vault keys.

## Household and space membership

- A private space has one readable member, though recovery/continuity envelopes
  may exist under separate policy.
- A shared space has a versioned SpaceKey and one envelope per active authorized
  device.
- Adding a member creates new envelopes after invitation acceptance and device
  proof; the server cannot manufacture them.
- Removing a member/device stops new envelope delivery and starts a new SpaceKey
  generation for future writes.
- Rotation state is revisioned and idempotent. Clients reject writes under a
  superseded generation after learning of the rotation fence.
- Historical ciphertext may remain decryptable to devices that already received
  the old key. Product UX must not claim retroactive revocation.

## Mutation protocol

For every mutation, the client supplies:

- `OperationId`;
- object ID/class/scope;
- expected current revision or create-only precondition;
- strictly newer candidate revision;
- ciphertext size/hash and body or approved upload handle;
- active device authentication;
- a device signature when the operation affects security state.

The server atomically validates authorization, idempotency, object bounds, and
revision preconditions before publishing the new change. Retrying an accepted
`OperationId` returns the original result. Reusing it with different input fails.

An attachment mutation does not publish the parent item revision until every
required chunk is uploaded and authenticated metadata is committed. Orphan
candidates are garbage-collected after a bounded period.

## Pull protocol

- Pull uses a monotonically advancing opaque cursor scoped to the authenticated
  account/household.
- Results are paginated and bounded by count and encoded bytes.
- A page contains metadata plus inline small ciphertext or signed, short-lived
  object download locations.
- The client verifies hashes, envelope authentication, scope, revision, and
  local resource bounds before durable acceptance.
- The client advances its durable cursor only after all objects in the page are
  authenticated and persisted.
- Cursor expiry triggers a bounded manifest reconciliation, never an unbounded
  whole-account response.

## Conflict policy

The service rejects stale expected revisions. It does not silently apply
last-writer-wins.

- Identical idempotent replay returns success.
- A safe client-defined merge may create a new revision only after decrypting
  and reviewing both parents locally.
- Unsafe or unknown conflicts preserve both encrypted candidates and require
  user resolution.
- Delete-versus-edit never resurrects silently. The UI presents the conflict or
  applies a previously reviewed deterministic rule for that object class.
- Security objects—memberships, device state, key generation, grants, recovery,
  emergency state—never use generic data merge. Their dedicated state machines
  decide transitions.

## Tombstones, history, and deletion

- Tombstones are authenticated client objects with monotonically newer
  revisions; the server observes only the routing tombstone flag required for
  synchronization.
- Retention must exceed the maximum supported offline-client window or require
  full reconciliation before an older client may push.
- History remains bounded and encrypted. Restore creates a new current revision;
  it never rewinds server revision counters.
- Account/household deletion has a documented grace period and backup lifecycle.
- Cryptographic destruction deletes/withholds applicable live keys, but cloud
  backup/version retention and formerly authorized copies remain documented
  limitations.

## SecureLinks

- A SecureLink references an encrypted immutable copy, not the live item key.
- URL capabilities contain at least 128 bits of CSPRNG entropy and are stored
  server-side only as a verifier/hash where practical.
- Optional email audience binding, expiry, view/download policy, access limits,
  and revocation are server-enforced.
- Link copies exclude password history, hidden access policy, recovery data, and
  unrelated attachment revisions.
- Access is rate-limited and creates a minimal security event without logging
  capability material or plaintext.

## Reminder delivery

Private-local reminders never enter the sync scheduling service as plaintext
schedule metadata. Their encrypted objects may sync normally.

For explicit cloud scheduling, an authorized client submits only the next
delivery instant, opaque reminder/account routing IDs, delivery channel, and
idempotency state. Generic notification delivery does not grant content access.
The client decrypts the synced reminder and advances recurring schedules.

## Travel Mode

- Spaces are marked safe-for-travel inside encrypted policy.
- Activation creates a signed device-local residency transition acknowledged by
  the service.
- The client removes non-travel SpaceKeys, related decrypted state, indexes, and
  local ciphertext after durable confirmation of recoverability from another
  authorized source.
- While active, the service withholds non-travel envelopes/objects from that
  device.
- Deactivation requires hosted authentication plus active device authorization
  and restores data through normal bounded sync.
- Browser/OS backups may retain older device storage; documentation must state
  that limitation.

## Compatibility

- Protocol, object, envelope, and payload versions are independent.
- Clients advertise supported ranges. The server refuses writes that would make
  required objects unreadable by the minimum supported household client version.
- Older clients fail before rewriting unknown mandatory fields.
- Server rollout remains backward-compatible before new clients depend on it.
- Database schemas migrate forward; rollback uses compatible application builds,
  not destructive down-migrations.

## Required negative tests

- cross-account/household/space object access;
- revoked, retired, or rebound device identities;
- stale revisions, replayed operation IDs, cursor rollback, and duplicate pages;
- interrupted uploads, swapped chunks, object transplant, and hash mismatch;
- malicious size/count/revision/version values;
- remove-member/write and rotate-key/write races;
- invitation and envelope delivery to the wrong principal/device;
- Travel Mode withholding/restoration and offline bypass attempts;
- SecureLink guessing, forwarding, expiry, revocation, and rate limits;
- backup/restore reconciliation with tombstones and key generations;
- mixed supported client versions during every security-sensitive transition.

## Completion gate

Sync is complete only when web and extension pass initial bootstrap,
incremental pull/push, concurrent edit, offline/reconnect, attachment resume,
member/device revoke, space-key rotation, tombstone reconciliation, Travel Mode,
and disaster-restore tests against the production-equivalent API/storage stack.
