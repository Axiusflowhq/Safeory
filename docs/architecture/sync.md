# Opaque Sync and Household Key Distribution

Status: target protocol architecture; not implemented end-to-end. The existing
`apps/api` opaque object endpoints are an initial transport surface.
`crates/vault-sync` now implements the bounded versioned account/household/
membership/space domain contracts and a ciphertext-preserving single-owner
migration plan. It also prepares and opens device-specific, generation-bound
space-key envelopes; atomic server rotation fencing and full client sync remain
incomplete. The API exposes the canonical `vault-sync` compatibility
advertisement, consumes its wire bounds, validates mutation/upload binding, and
atomically persists exact-input operation-ID outcomes with opaque headers. The
browser contracts package validates that bounded advertisement and negotiates
protocol, object-header, and envelope versions before sync. It also implements
strict opaque contract parsing plus authenticated, ciphertext-verifying
list/download/upload transport. Encrypted vault item records now have a strict
browser transport adapter that creates create-only or exact-revision/hash-fenced
opaque mutations and rejects pulled bodies whose encrypted item identity,
revision, payload version, digest, or object class differs from the authenticated
header. The item adapter also implements fail-closed three-way
reconciliation against the last durably accepted server header: it distinguishes
safe remote fast-forwards, exact replays, local-ahead ciphertext, and concurrent
edits without decrypting or falling back to last-writer-wins. A CAS-fenced
IndexedDB acceptance coordinator durably persists those baselines and encrypted
conflict candidates. It applies remote ciphertext through an application-supplied
durable callback before advancing the baseline, so an interrupted baseline write
is repaired by replay rather than misclassified as a local edit. `VaultSession`
now supplies that callback through an exact-ciphertext WASM compare-and-swap,
authenticating the candidate under the in-WASM root key before persisting the
resulting snapshot with its existing cross-tab durability fence. Plaintext stays
inside WASM and the unlocked root key is preserved. The extension supplies the
same callback through its serialized `chrome.storage.local` snapshot queue,
preserving its background-worker key boundary. The initial single-owner
topology bootstrap is now crash-safe: generated
household, membership, private-space, and metadata-object IDs are persisted in
IndexedDB before publication, exact publication retries reuse that draft, and
the migration inventory includes every encrypted vault record except the
device-local reload marker. The composed browser runtime pulls and durably
accepts remote records before scanning that inventory for local-ahead
ciphertext. It reconstructs missing outbox writes with content-derived stable
operation IDs, chains multiple queued local revisions, and obtains the
authenticated permanent-deletion bit inside WASM for opaque tombstone routing.
A bounded credential-free IndexedDB push outbox
retains canonical mutation/ciphertext pairs until a matching upload response is
durably acknowledged, so interrupted acknowledgements replay by operation ID.
A web settings control now enrolls through the deployment's same-origin
`/api/` proxy. The development registration bearer remains ephemeral, device
credentials stay wrapped under a non-extractable IndexedDB key, and only API,
account, and device routing identifiers enter local storage. It re-authenticates
the unlocked vault, generates and confirms the Account Secret, then durably
queues and flushes the account-bound remote-root envelope before topology
publication. Once unlocked, the web runtime resumes that credential and runs
serialized sync after durable local mutations, browser reconnect/foreground
events, manual requests, and a 30-second bounded interval. The MV3 extension now
performs equivalent explicit development enrollment, including Account Secret
confirmation, root re-authentication, and durable root-envelope publication. It
stores only non-secret routing metadata in extension storage, resumes its wrapped
credential after unlock, and coalesces mutation, manual, unlock, and one-minute
alarm triggers. Its remote accepts share the local mutation durability queue, and
locking aborts active network work. MV3 worker reclamation deliberately requires
another unlock because usable vault keys are not persisted. Reviewed
production identity, new-device approval, and recovery enrollment remain to be
integrated, so the development web and extension controls create independent
accounts rather than claiming same-account convergence.
A pull coordinator verifies each downloaded body, waits for an idempotent
durable-acceptance callback, and only then compare-and-swap checkpoints that
change sequence. The API now persists revision-fenced household topology,
accepts exact publication retries idempotently, and enforces household/space
authorization on object list, download, and upload paths. Cross-account
shared-object routing and production same-account web/extension convergence
remain incomplete.

The browser contracts package also parses the canonical versioned account,
household, membership, space, space-member, and single-owner migration topology.
It rejects unknown fields, unbounded collections, unsafe integers, duplicate or
inconsistent references, missing active ownership, private-space over-sharing,
invalid role access, and stale key-generation bindings before application use.
Rust and browser implementations also share a fail-closed routing policy:
account access requires the bound device, household writes require an active
owner or organizer, and space read/write/manage actions require the matching
device-specific membership and access level. This server-visible decision is
necessary but never substitutes for possession of the client-side space key.

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
2. Generate the Account Secret, stable device UUID, and device cryptographic
   identities on the client.
3. Create the AccountRootKey and initial private household/space locally.
4. Upload only public device registration, encrypted root/space envelopes, and
   opaque ciphertext objects.
5. Return one-time device authorization material only once; persist only its
   verifier/hash server-side.

ADR 0006 defines the Account Secret construction and root-wrap migration. The
Rust/WASM core implements the account-bound remote envelope and fresh-device
root import. The opaque transport reserves one non-tombstonable, 4 KiB
`account_bootstrap` object per account: its object UUID equals the account UUID,
its account scope and V1 payload/envelope versions are validated in both Rust
and TypeScript, and updates use the ordinary hash-and-revision CAS. An
authenticated device can fetch its canonical metadata directly before the
ciphertext body, avoiding a scan of unrelated items. The web and extension
development setup flows now implement the first-device confirmation and
publication path. Production identity plus the server enrollment/recovery
coordinator remain.

### Additional device

1. The new device authenticates the hosted account but has no content key.
2. It creates ADR 0007's self-signed request binding its account/device UUIDs
   and X25519/Ed25519 public keys.
3. An active device or reviewed recovery path explicitly authorizes enrollment
   and signs a recipient-encrypted device-credential grant.
4. The new device proves X25519 possession by opening and using that grant, then
   verifies the approver against the authenticated active-device inventory.
5. The service atomically activates the pending device and records a minimal
   security event before ordinary sync access is allowed.
6. The joining device supplies its master passphrase and Account Secret to open
   the account bootstrap inside WASM and install a new device-local root wrap.

The request/grant cryptographic core, browser secure-key-store adapter, and
durable server state machine are implemented. Pending bearers are isolated from
ordinary authentication, reserve bounded slots, expire, can be cancelled, and
activate atomically with a minimal event. Durable client approval coordination,
post-activation inventory confirmation, and reviewed UX remain.

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
- independently versioned protocol, mutation, object-header, envelope, and
  encrypted-payload framing;
- object ID/class and account/household/space routing scope, which the server
  must match against the authenticated device rather than trust independently;
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

### Initial compatibility matrix

`vault-sync` is the canonical wire-contract owner. The API, web app, and
extension must consume these contracts rather than create parallel enums or
version rules.

| Layer | Current write version | Reader behavior | Server behavior |
| --- | ---: | --- | --- |
| Compatibility advertisement | 1 | Reject unknown required fields and invalid/reversed ranges | Select the highest common version independently for each advertised layer |
| Sync protocol | 1 | Reject unsupported protocol versions before object processing | Refuse requests with no common protocol version |
| Opaque mutation framing | 1 | Require a non-nil operation ID and exact revision precondition | Persist idempotency outcome; same ID with different input fails |
| Opaque object header | 1 | Validate scope IDs, safe-integer revision, versions, and ciphertext bounds | Match supplied scope to authenticated authorization; never infer plaintext class details |
| Space-key envelope | 1 (`space-key:v1` over share envelope v2) | Require exact authenticated routing context and generation | Route ciphertext only; atomic rotation fencing remains to be implemented |
| Encrypted object payload | Class-specific positive version | Decrypting client rejects unsupported mandatory schema versions | Opaque to server; writes must remain readable by the minimum supported household client |

The initial advertisement negotiates protocol, object-header, and outer
key-envelope versions as separate ranges. Payload versions stay on each opaque
object header because item, attachment, activity, and capsule schemas evolve
independently. Adding a new object class, required field, or incompatible
transition requires a new version and mixed-client negative tests; an enum value
unknown to an older client fails before mutation.

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
