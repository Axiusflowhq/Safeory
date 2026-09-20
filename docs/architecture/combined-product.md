# Combined Product Architecture

Status: target product contract. Implemented behavior remains identified in
`PLAN.md`; this document defines the architecture Safeory must reach.

## Product definition

Safeory is a zero-knowledge family life vault that combines:

1. the consumer credential-management capabilities expected from 1Password
   Individual and Families; and
2. the household organization, collaboration, continuity, and legacy-planning
   capabilities expected from Trustworthy.

Safeory is not attempting parity with 1Password Business, Enterprise, or
Developer products. Workforce SSO/provisioning, SSH agents, CLI secret
injection, infrastructure-secret automation, and enterprise device posture are
outside the consumer product contract unless added by a later ADR.

The combined product must feel like one system. Credentials, household records,
files, reminders, collaborators, recovery, and legacy plans share one account,
identity, encryption, sync, audit, and device model; they are not separate
products joined only in the navigation.

## Competitive baseline and parity governance

The capability baseline was reviewed on 2026-09-20 against the official
[1Password features](https://1password.com/features),
[1Password Families/password manager](https://1password.com/product/password-manager),
[1Password Travel Mode](https://support.1password.com/travel-mode/),
[Trustworthy organization model](https://help.trustworthy.com/en/articles/12612161),
[Trustworthy collaborator access](https://help.trustworthy.com/en/articles/12394561),
and [Trustworthy reminders](https://help.trustworthy.com/en/articles/11095105).
Competitor behavior changes over time; those pages are references, not Safeory
specifications.

Before each connected beta and production release, maintain a testable matrix
with every relevant capability marked `Implemented`, `Safeory equivalent`,
`Later`, or `Explicit non-goal`. Marketing may claim parity only with the
declared consumer matrix that passes its release tests. Security or privacy
differences are described as design choices, not silently omitted features.

## Product principles

- **Zero knowledge by default.** Vault plaintext and usable vault keys remain on
  authorized devices. Any feature that requires disclosure must be explicit,
  narrowly scoped, optional, and documented.
- **Local-first, synchronized.** Core read/write work remains possible offline.
  Cloud sync converges authorized clients without becoming the plaintext source
  of truth.
- **Private and shared spaces are both first-class.** Every household member may
  have private data while participating in shared household spaces.
- **Continuity is policy, not a backdoor.** Recovery restores an authorized
  principal; emergency and legacy flows release only explicitly selected keys.
- **Automation remains reviewable.** Imports, extraction, reminder suggestions,
  and filing suggestions enter an Inbox and require user confirmation.
- **Security claims follow shipped behavior.** Planning metadata, local
  simulations, or crypto primitives are never described as remote release,
  verified identity, guaranteed deletion, or cross-device sync.

## Target capability contract

### Credential security

- structured logins with multiple origins, username, password history, TOTP,
  passkeys, notes, custom fields, and attachments;
- password/passphrase generation, security-health analysis, reuse/age alerts,
  optional k-anonymity breach checks, and passkey/2FA upgrade suggestions;
- save/update capture and explicit-origin autofill in supported browsers;
- addresses, payment cards, identities, and other form-fill records;
- imports from major password managers and portable export;
- shared spaces, item sharing, expiring SecureLinks, and revocation;
- Travel Mode implemented as cryptographic/local removal of non-travel spaces,
  not a UI visibility toggle;
- recovery kit, account recovery, device inventory, remote revoke, auto-lock,
  OS-keystore/biometric unlock where the platform supports it.

### Household operating system

- structured categories for family identity, medical, finance, property,
  insurance, vehicles, possessions, receipts, tax, legal, business, contacts,
  subscriptions, credentials, and general documents;
- pages/items with details, notes, files/folders, connections, reminders, and
  history;
- an Inbox for uploaded, scanned, forwarded, captured, and imported material;
- local/private extraction of titles, fields, dates, connections, summaries,
  and filing suggestions, with human review before durable changes;
- custom and recurring reminders with an explicit privacy model for scheduling
  and notification delivery;
- full, partial, and legacy collaborator experiences;
- activity history, temporary external sharing, portable export, and account
  deletion;
- responsive web access first, with capture/offline/platform limitations stated
  honestly until native clients exist.

### Continuity and legacy

- trusted-person invitation and device-key enrollment;
- per-space and per-item view/edit permissions;
- emergency/incapacity/death conditions, waiting periods, approval thresholds,
  owner notification, denial, revocation, release, expiry, and audit;
- selected legacy access, private-forever records, and cryptographic destruction
  intent;
- Plan Test/readiness simulation that never starts a real release;
- trustee portal that decrypts released capsules only on an authorized trustee
  device.

## Account and household domain model

```text
Account
  |-- account identity and subscription
  |-- authorized devices
  `-- memberships
        |
        v
Household
  |-- members and roles
  |-- collaborators and legacy principals
  |-- audit/security events
  `-- spaces
        |-- Private space (one member)
        |-- Shared household space
        |-- Purpose space (travel, estate, advisor, etc.)
        `-- items, folders, reminders, and encrypted indexes
```

An account is a sign-in and device-authorization boundary. A household is a
collaboration boundary. A space is a cryptographic sharing and organization
boundary. An item remains the smallest independently revisioned and shareable
content object.

Required roles are `owner`, `organizer`, `member`, `full_collaborator`,
`partial_collaborator`, and `legacy_collaborator`. Roles grant management
capabilities; readable content still requires an appropriate encrypted space or
item key. Server authorization and cryptographic authorization must both pass.

The current single-owner vault maps to one account, one household, and one
private space during migration. Stable UUIDs and explicit versioned migrations
must preserve existing encrypted items and grants.

## Target key hierarchy

```text
Master passphrase + production Account Secret/device enrollment secret
  -> reviewed unlock KDF / key-combining construction
  -> unwrap AccountRootKey
       |-- account/device authorization material
       |-- private-space wrap keys
       |-- household-space membership envelopes
       |-- item keys
       |-- attachment keys
       |-- recovery wraps
       `-- emergency/legacy capsule keys
```

The implemented passphrase-only root wrap remains the device-local format.
ADR 0006 defines and the Rust/WASM core implements the separate high-entropy
Account Secret envelope for remotely stored root bootstrap, protecting it from
password-only offline guessing. Server publication, enrollment/recovery UX, and
external review remain cloud-launch gates. Cognito authentication is not a
replacement for this cryptographic factor.

Spaces require independently rotatable keys. Removing a member rotates the
affected space key for future writes and prevents future key delivery; it
cannot make plaintext or keys already received by that member disappear.
Per-item keys remain random. Sharing wraps keys rather than re-encrypting
plaintext on the server.

Travel Mode requires a space-level residency policy. Non-travel space keys and
local ciphertext are removed from a participating device and restored only
after authenticated re-enrollment/sync. Merely hiding records is insufficient.

## Synchronization contract

The versioned sync protocol must cover:

- account and device bootstrap;
- household membership and space-key envelope delivery;
- opaque object manifests, incremental cursors, pagination, and bounded reads;
- item, attachment, history, reminder, audit, and tombstone object classes;
- offline mutation queues and idempotent retries;
- exact revision/CAS conflicts and explicit human resolution where merging is
  unsafe;
- deletion retention, cryptographic erasure, and backup/versioning interaction;
- remote device revocation and key-envelope rotation;
- web/extension convergence and protocol compatibility across client versions;
- initial download, reconnect, interrupted attachment transfer, and disaster
  recovery.

The server does not interpret encrypted item kinds or tombstone meaning. It may
enforce account/household/device authorization, quotas, revisions, object
framing, and durable workflow state using the minimum permitted metadata.

## Private ingestion and automation

Safeory supports four ingestion classes:

1. local upload/drag-and-drop;
2. browser capture and explicit share-to-Safeory actions;
3. mobile camera/scanner when a capable client exists; and
4. optional connected imports such as Gmail.

Local upload and capture encrypt before network persistence. Ordinary email
forwarding cannot be described as zero knowledge because an SMTP receiver sees
the message and attachment before client-side encryption. It is therefore not
allowed under the default architecture. A future connector must use one of:

- client-side retrieval and local encryption;
- a user-operated bridge that encrypts before delivery; or
- a separately consented disclosure mode with precise retention and threat
  documentation that is not branded zero knowledge.

OCR, classification, summarization, field extraction, and connection/reminder
suggestions run locally by default. A future remote processor requires an ADR,
per-operation consent, provider/retention disclosure, and a guarantee that the
result does not silently expand server-visible metadata.

All automated output lands in an encrypted Inbox as suggestions. Only an
authorized user action promotes suggestions into durable records.

## Reminder and notification privacy

Reminder content, linked-item identity, and notes remain encrypted. The product
must offer two explicit modes:

- **Private local mode:** authorized clients schedule and display notifications;
  no reminder date or content is disclosed to the service, and delivery is not
  guaranteed while every client is offline.
- **Cloud scheduled mode:** the user opts in to disclose the minimum schedule
  envelope needed to wake a client or send a generic notification. Email/push
  content contains no item title, category, note, or secret. Opening Safeory on
  an authorized device reveals the decrypted reminder.

Recurring reminder rules are encrypted. When cloud scheduling is enabled, the
server receives only the next required delivery instant, opaque reminder ID,
household/account routing ID, and delivery state.

## Sharing and collaboration

- Full collaborators receive explicitly authorized shared-space membership;
  they never inherit private spaces.
- Partial collaborators receive selected space or item key envelopes with
  separate view/edit capabilities.
- Legacy collaborators receive no current content keys solely because they are
  designated for legacy access.
- SecureLinks share an encrypted copy or immutable revision with audience,
  expiry, view/download policy, and revocation. They never expose the live
  owner item key or password history.
- Every invitation, membership change, share, recovery, and emergency action
  creates a durable security event with opaque references and a signed client
  assertion where attribution matters.

## Audit model

The service keeps a minimal append-only security event stream for authorization
and workflow events. Human-readable item activity remains encrypted. Events are
versioned, idempotent, account/household scoped, and tamper-evident through a
hash chain or equivalent reviewed construction. Client signatures prove device
origin where required; they do not prove a person's real-world identity.

Audit retention, export, redaction, administrator access, and deletion behavior
must be defined before collaboration or emergency release ships.

## Client surfaces

- **Web app:** deep management, Inbox review, files, reminders, collaborators,
  recovery, devices, exports, Trust Engine, and Plan Test.
- **Browser extension:** credential save/fill, passkeys/TOTP where browser APIs
  allow, quick add/capture, search, and compact household views.
- **Responsive mobile web:** read/manage/copy workflows with documented browser
  limitations.
- **Native clients:** not a current commitment, but required for native mobile
  autofill, dependable background reminders/scanning, broad biometric/keystore
  integration, or desktop universal autofill. These capabilities must not be
  claimed until an ADR adds the relevant client.

## Delivery gates

### Local beta

- implemented local-vault gates remain green;
- all record kinds, attachments, recovery, export, reminders, and trash work;
- security claims match the single-device behavior.

### Connected beta

- account/device enrollment and Account Secret design are reviewed;
- private/shared spaces and membership migrations work;
- web and extension sync pass offline/conflict/revocation tests;
- collaborator invitations and SecureLinks are end-to-end;
- production-like backup/restore succeeds without server plaintext.

### Continuity beta

- signed trustee requests and durable coordinator preserve the local state
  machine invariants;
- owner warning, deny, revoke, expiry, and policy/revision invalidation work
  across devices;
- trustee delivery, Plan Test, and audit UX pass abuse-case testing.

### Production launch

- AWS IaC, observability, backups, restore drills, load/soak tests, and incident
  procedures pass;
- external review covers crypto, sync, sharing, recovery, extension, and Trust
  Engine boundaries;
- credential health, TOTP, imports, supported-browser autofill, household
  organization, reminders, collaboration, and portable export meet the declared
  launch matrix;
- unsupported 1Password/Trustworthy capabilities are listed publicly rather
  than implied.

## Scope maintenance

`PLAN.md` records implementation status. `docs/ROADMAP.md` orders delivery.
This document owns the combined-product architecture. Any change to the product
boundary, household/space model, normal unlock factors, server-visible metadata,
or remote processing requires an ADR and corresponding threat-model update.
