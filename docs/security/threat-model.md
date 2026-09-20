# Threat Model

Status: browser/WASM + extension + AWS-hosted API baseline. Update this document before each security-sensitive feature ships.

## Assets

- Vault plaintext, attachments, credentials, recovery codes, and emergency instructions.
- AccountRootKey and derived/wrapped item keys.
- Device private keys and recovery-key material.
- Production Account Secret/device-enrollment material and private/shared space
  keys.
- Trusted-person authorization and emergency-grant state.
- Household membership, collaborator permissions, SecureLinks, reminder
  schedules, Inbox contents, and security/activity history.
- Integrity of revisions, tombstones, sync state, and device authorization.

## Trust boundaries

1. Rust cryptographic/domain code and the `vault-wasm` boundary.
2. Web-app JavaScript/DOM and WASM linear memory.
3. Browser IndexedDB ciphertext persistence.
4. Extension background worker, trusted extension pages, browser-managed storage, and untrusted page content scripts.
5. Browser/OS clipboard, file-download, print, and process-memory boundaries.
6. Network boundary.
7. AWS edge/account/backend boundary: CloudFront, Cognito, Rust API, RDS PostgreSQL, S3, Valkey/workers, SES, IAM/secrets, and CloudWatch.
8. Trusted recipient devices.
9. Household members, collaborators, SecureLink recipients, and their devices.
10. Optional ingestion, notification, OCR, or AI providers when a future ADR
    explicitly enables them.

## Threat register

| Threat | Consequence | Primary mitigation | Residual risk |
| --- | --- | --- | --- |
| Stolen PostgreSQL database | Account/security metadata exposed | Minimize plaintext metadata; opaque IDs; E2EE vault objects | Metadata correlation remains visible |
| Stolen object-storage bucket | Ciphertext exfiltration/offline attack | Per-item/file keys, AEAD, strong root-key wrapping | Weak passphrases still weaken offline resistance |
| Stolen remote root-wrap material | Password-only offline guessing | ADR 0006 account-bound envelope combines bounded Argon2id with a client-only 256-bit Account Secret; recovery stays independently wrapped | Production publication/enrollment still requires external review; loss of every authorized device and recovery factor can make data unrecoverable |
| Malicious backend administrator | Unauthorized metadata actions or early policy transitions | Backend never receives usable vault keys; strict auth/audit | Admin can deny service or release encrypted capsules early |
| Backend compromise | Modification/replay/availability attacks | Authenticated envelopes, revisions, device auth, replay checks | Availability cannot be guaranteed |
| Compromised Valkey/worker queue | Retry abuse, rate-limit bypass, duplicated jobs | Durable authorization stays in PostgreSQL; idempotent work | Queue compromise can delay or amplify work |
| Proxy/application log exposure | Metadata, bearer token, or ciphertext copied into logs | No request-body/auth-secret logging; structured redaction | Network/account metadata remains observable to operator |
| Compromised AWS account/IAM principal | Metadata/object access, destructive control-plane actions | Least-privilege IAM, short-lived/OIDC credentials, MFA/admin separation, CloudTrail, backups, no vault keys server-side | Attacker can deny service or exfiltrate ciphertext/server-visible metadata |
| Cognito compromise/misconfiguration | Account-session takeover or unauthorized device-enrollment attempts | Cognito is account identity only; server-side account scoping; separate revocable Safeory device identity; security-event logging | Compromised account identity can authorize operations allowed to that account but still does not directly reveal vault decryption keys |
| Device-enrollment relay substitution | Attacker replaces joining keys or the delivered bearer | ADR 0007 self-signed request binds both joining keys; approver-signed grant is X25519 recipient-encrypted and account/request/device bound; pending bearers cannot authenticate sync and activate atomically; joining client verifies active approver inventory before saving credentials | Unlocked approver compromise can still authorize a malicious device; application UX and external review remain |
| Compromised user passphrase | Device-local root wrap can be attacked; remote root still needs Account Secret | Argon2id, strong UX, rewrap on change, ADR 0006 two-factor remote envelope | Known passphrase plus a local wrap, or plus Account Secret and remote wrap, is catastrophic |
| Stolen or compromised device | Plaintext/key theft while unlocked | Encrypted local persistence, explicit lock, minimal redacted projections | Malware can inspect process memory/screens while unlocked |
| Stolen browser device-key database | Recipient X25519/Ed25519 private-key ciphertext and public metadata exposed | Dedicated IndexedDB; private bundle AES-GCM wrapped under a browser-generated non-extractable 256-bit key; public metadata bound as AAD | Same-origin script execution can still invoke the stored CryptoKey; this is not an OS/hardware keystore |
| Web-app script/XSS compromise | Reads unlocked plaintext or WASM memory | Strict CSP, pinned dependencies, redacted projections, explicit detail fetches | WASM is not a sandbox from same-origin JavaScript |
| Stolen browser reload-resume capability | Same-tab vault can be resumed without re-entering the master passphrase | Fresh 256-bit session secret; dedicated HKDF/AAD domain; sessionStorage only; rotate after resume; clear on explicit lock; accept only on reload navigation | Same-origin script compromise can read the capability while the tab session is unlocked |
| Malicious login page | Attempts cross-site credential release | Sender-derived top-frame origin; exact HTTP(S) match; trusted-click lookup; per-tab/origin throttle; one-shot fill authorization | Once explicitly filled, page JavaScript can read its own fields |
| Forged extension message | Confused-deputy access to privileged commands | Separate sender checks for content scripts and extension pages; ignore caller-supplied origin | Future message types can widen the surface if classified incorrectly |
| Stale browser tab | Overwrites newer local state | IndexedDB compare-and-swap; serialized mutation/snapshot/persist queue; fail-closed poison on durability failure | Losing tab must reload rather than merge |
| Malformed/oversized browser snapshot | Memory/CPU amplification or inconsistent encrypted state | Schema/count/duplicate-ID/revision/encoded-size validation before restore | Valid data within limits still costs bounded resources |
| Oversized browser input | Memory/CPU/storage amplification | Shared portable item-size bounds before encryption/persistence | Browser must allocate a rejected input once |
| Clipboard leakage | Secret retained outside Safeory | Explicit copy; ownership-token compare-and-clear where browser lifetime permits | Popup lifetime, permissions, OS history/sync, or other software may retain it |
| Logs/crash dumps | Plaintext leakage | Redacted errors/logging; no secret serialization to logs | Browser/OS crash capture can include memory |
| Replay/rollback | Stale mutation or object accepted | Revisions, tombstones, operation IDs, authenticated metadata | Offline clients may not know newer remote state |
| Sync conflicts | Data loss/overwrite | Object revisions, CAS/conflict policy, tombstones | Human resolution may still be required |
| Malicious or removed household member | Reads future shared data or mutates household state | Dual server/crypto authorization, explicit space membership, device revoke, key rotation, signed security events | Previously received plaintext or keys cannot be recalled |
| Organizer overreach | Household organizer reads a member's private records | Private-space keys never follow administrative role alone | Compromised member device can still reveal that member's private space |
| Space-key rotation failure | Revoked member continues receiving future updates | Versioned membership envelopes, rotation fencing, client compatibility tests | Rotation cannot erase earlier copies |
| Space-key envelope transplant | A key is accepted for the wrong space, generation, membership, or device | Authenticated fixed-binary inner context must match bounded outer routing fields and caller expectations | An authorized recipient still learns the key intentionally addressed to that device |
| Forged space-key sender claim | A recipient represents a self-forged X25519 envelope as owner-issued | Treat claimed sender only as context; require separate signed security mutation plus active-device authorization before server publication | Device signatures prove key possession, not human identity or intent |
| SecureLink guessing or forwarding | Unauthorized external access to a shared copy | High-entropy capability, audience binding where selected, expiry, revocation, rate limits, encrypted immutable copy | Authorized recipient can copy plaintext |
| Travel Mode implemented as hiding | Sensitive vault remains physically recoverable on device | Remove non-travel space keys and local ciphertext; test authenticated restoration | OS/browser backups may retain prior device data outside immediate control |
| Reminder metadata leakage | Household events or sensitive conditions inferred | Private-local default; opt-in minimum schedule envelope; generic notifications | Timing and frequency leak in cloud mode |
| Plaintext email ingestion | Server/provider sees sensitive attachments | Exclude ordinary SMTP forwarding from zero-knowledge mode; retrieve/encrypt client-side | User-selected disclosure mode intentionally widens trust boundary |
| Remote OCR/AI disclosure | Provider retains or trains on household documents | Local processing default; per-operation consent and reviewed provider/retention ADR | Consented disclosure cannot be cryptographically undone |
| Poisoned document/import | Parser exploit, resource abuse, or malicious filing suggestions | Sandboxed/bounded parsers, MIME validation, local processing, encrypted review Inbox, explicit promotion | Complex document formats retain parser risk |
| Forged or missing activity history | Collaborator actions are misattributed or hidden | Minimal append-only/tamper-evident security events plus signed device assertions | Device signatures prove device possession, not the human actor |
| Emergency-state race | Release after deny/revoke | Portable local state machine already enforces revision/policy fencing and idempotent deny/revoke/release semantics; production PostgreSQL coordinator must preserve the same invariants and fail closed | Control-plane failure can delay valid actions |
| False death/incapacity claim | Premature legacy release | Waiting periods, multi-party approval, owner-device alerts, evidence/appeal policy, signed requests, deny/revoke wins | No technical control can perfectly establish a real-world condition |
| Recovery-flow takeover | Root access stolen | High-entropy recovery secret; no server recovery backdoor | Recovery-key theft is catastrophic |
| Brute-force attempts | Account/passphrase guessing | Argon2id offline resistance; API/reverse-proxy rate limits | Weak passphrases remain weaker |
| Supply-chain compromise | Malicious build/dependency | Lockfiles, minimal dependencies, audit/deny policy, CI | Registry/account compromise remains possible |

## Browser/WASM assumptions

- The web app persists only ciphertext `KVSnapshot` data in IndexedDB. Browser-local compare-and-swap versions fence stale-tab writes. A post-mutation snapshot/save failure poisons and locks the session instead of continuing on divergent memory.
- A normal same-tab document reload may resume an already unlocked web vault through a short-lived `sessionStorage` capability. The capability is a fresh 256-bit random secret plus a separately domain-separated encrypted root-key envelope; it is not the master passphrase, recovery secret, or raw root key. It is accepted only for a navigation reported as `reload`, rotated after successful resume, and cleared on explicit lock or failed resume. Because `sessionStorage` is readable by same-origin JavaScript, the capability is bearer-equivalent while present and does not mitigate XSS.
- Browser `MemStore` validates snapshot schema, object-count ceiling, duplicate IDs, encrypted item/wrap encoded-size bounds, and supported revision range before accepting a restored snapshot. Validation is ciphertext-only.
- Normal web lists cross the WASM boundary only as redacted summaries. Today/deadline data crosses only as `{itemId, kind, title, label, date, daysUntil, revision}`. Full fields/notes cross only when the user explicitly opens one record.
- The Emergency Card and recovery secret are explicit plaintext UI surfaces only while unlocked. They are never persisted as plaintext browser state.
- `vault-wasm` zeroizes Rust-owned key wrappers on lock, but generated bindings expose linear memory to same-origin JavaScript. CSP, dependency integrity, extension isolation, and reducing plaintext returned to JS remain primary controls.
- Browser strings and DOM values cannot be reliably zeroized. UI code minimizes lifetime and avoids logs, URLs, analytics, server rendering, and browser storage for decrypted values.
- Long-lived trusted-recipient X25519 and Ed25519 private material is stored separately from vault snapshots in the `safeory-device-keys` IndexedDB database. The 64-byte private bundle persists only as AES-GCM ciphertext under a non-extractable Web Crypto key stored by structured clone; device UUID and both public keys are authenticated as AAD. Raw private bytes cross the JS/WASM boundary only transiently during wrap/unwrap and are overwritten best-effort immediately afterward. The wrapping key is not exported and device keys are deliberately excluded from normal vault backup/export.
- A non-extractable browser CryptoKey is defense against accidental/plaintext persistence, not against XSS or a compromised same-origin runtime: hostile same-origin JavaScript can invoke the key and observe transient unwrapped bytes. OS-backed hardware/biometric key storage remains a separate future hardening step.
- The web and extension currently maintain separate local ciphertext stores. Until sync convergence ships, neither surface may imply records automatically appear in the other.
- Browser attachment/export flows must use explicit user-mediated browser APIs and keep encryption/decryption in the client security boundary. Native SQLite attachment/backup utilities remain library/test capabilities, not a shipping client surface.

## Extension assumptions

- Only the extension background worker owns the unlocked `WasmVault`. Content scripts receive neither keys nor a whole decrypted vault.
- Credential summaries are fetched only after a trusted click on the Safeory affordance. The background derives origin from `MessageSender`, requires exact normalized HTTP(S) scheme/host/effective-port matching, rate-limits per tab+origin, and issues a short-lived one-shot fill authorization consumed before decrypting a selected credential.
- Extension-page privileged commands require a same-extension page sender without a tab sender. Content-script and extension-page message surfaces use separate checks.
- Cross-origin frames are not treated as the top-level origin. Autofill must not cross origin boundaries by caller assertion.
- Password copy currently performs best-effort delayed compare-and-clear from the popup. Closing the popup or losing clipboard permission can prevent cleanup; OS clipboard history/sync is outside Safeory's erasure guarantee.

## Household, space, and automation assumptions

- Account roles authorize management operations but never substitute for a
  private/shared space key.
- Household organizers do not automatically receive another member's private
  space keys.
- Removing a member/device blocks future delivery and rotates affected space
  keys; it cannot retract previously decrypted information.
- Space-key envelopes authenticate space, generation, membership, recipient
  device, and sender-device context. Their X25519 sender field is not a
  signature; remote rotation publication requires a separately signed mutation.
- Legacy designation alone grants no current space or item key.
- Travel Mode is a key/ciphertext residency control, not a filtering feature.
- Automated extraction and filing suggestions are untrusted input and enter an
  encrypted review Inbox before durable changes.
- Ordinary SMTP forwarding is outside the zero-knowledge default because the
  receiver observes plaintext. Remote OCR/AI or disclosure-mode ingestion
  requires a separate explicit trust boundary.
- Cloud reminder mode reveals timing and opaque routing only after opt-in;
  notification content remains generic.
- Device signatures attribute an action to a device key. They do not prove the
  real-world identity, intent, capacity, or survival status of a person.

## AWS/server assumptions

- The API never receives usable vault decryption keys or vault plaintext.
- Cognito owns hosted account identity/session state but never receives vault passphrases, recovery secrets, usable vault keys, or vault plaintext.
- RDS PostgreSQL is authoritative for server-visible account/device/revision/idempotency/policy state. Valkey is ephemeral and cannot authorize durable security transitions by itself.
- S3 contains opaque encrypted objects. Cross-account object access fails closed and server logs must not contain bearer tokens or object bodies.
- SES email contains notifications/invitations only, never vault plaintext or decryption material.
- CloudFront/CloudWatch/IAM operational data follows the same metadata-minimization and secret-redaction rules as the application.
