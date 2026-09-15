# Threat Model

Status: Phase 0 baseline. Update this document before each security-sensitive feature ships.

## Assets

- Vault plaintext, attachments, credentials, recovery codes, emergency instructions.
- AccountRootKey and derived/wrapped item keys.
- Device private keys and recovery key material.
- Trusted-person authorization and emergency grant state.
- Integrity of revisions, tombstones, and device authorization state.

## Trust boundaries

1. Unlocked local Rust core.
2. Local encrypted SQLite database.
3. Tauri IPC boundary and WebView renderer.
4. OS secure-storage boundary (future Phase 0/1 work).
5. Network boundary.
6. Cloudflare Workers/D1/R2/Durable Objects/Queues.
7. Trusted recipient devices.

## Threat register

| Threat                            | Consequence                                        | Primary mitigation                                                        | Residual risk                                               |
| --------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Stolen Cloudflare database        | Account/security metadata exposed                  | Minimize plaintext metadata; opaque IDs; E2EE vault records               | Metadata correlation remains visible                        |
| Stolen R2 bucket                  | Ciphertext exfiltration/offline attack             | Per-item/file keys, AEAD, strong root-key wrapping                        | Weak passphrases still weaken offline resistance            |
| Malicious backend administrator   | Unauthorized metadata actions/early release        | Backend never receives usable vault keys; strict auth/audit               | Admin can deny service or release encrypted capsules early  |
| Backend compromise                | Modification/replay/availability attacks           | Authenticated envelopes, revisions, device auth, replay checks            | Availability cannot be guaranteed                           |
| Compromised user passphrase       | Root key may be unwrapped if wrap record is stolen | Argon2id, strong UX, notifications, rewrap on change                      | Known passphrase plus wrap material is catastrophic         |
| Stolen desktop computer           | Offline database theft                             | Encrypted secret-bearing records; passphrase KEK; OS secure storage later | Unlocked sessions/OS compromise can expose plaintext        |
| Compromised trusted contact       | Authorized subset exposed                          | Granular grants; recipient-bound key wrapping; revocation before release  | Already decrypted copies cannot be recalled                 |
| Malicious trusted-contact request | Premature access attempt                           | Waiting policy, notifications, denial/revocation, rate limits             | Compromised server can release ciphertext early             |
| Revoked trusted contact           | Future unauthorized release                        | Invalidate unreleased grants; rotate affected wrapping material           | Previously decrypted copies persist                         |
| Compromised device                | Plaintext/key theft while unlocked                 | Manual + 10-minute inactivity lock; generation-fenced renderer cleanup; secure storage planned | Malware can read process memory/screens while unlocked |
| Malicious WebView content         | IPC invocation/data theft                          | Bundled assets, strict CSP, narrow domain commands                        | Renderer compromise retains legitimate capabilities         |
| IPC abuse                         | Unauthorized core operations                       | Typed domain commands; authorization in Rust core                         | Logic bugs remain possible                                  |
| Oversized renderer input          | Memory/CPU/storage amplification                    | Portable Rust item-size limits before encryption and persistence          | IPC must still allocate a rejected input once               |
| XSS                               | Renderer compromise                                | No remote code, strict CSP, escaping, no eval                             | Dependency/app bugs may still inject content                |
| CSRF                              | Unauthorized browser-surface actions               | SameSite/Secure/HttpOnly cookies, origin checks, anti-CSRF patterns       | Applies to future web surfaces                              |
| Supply-chain compromise           | Malicious dependency/build artifact                | Lockfiles, minimal deps, audits, CI scanning                              | Registry/account compromise remains possible                |
| Clipboard leakage                 | Secret retained outside app                        | Backend-only password copy; ownership-checked 30s clear; Windows compare+clear holds the global clipboard lock; early clear after session invalidation | OS clipboard history/sync/tools may retain copied secrets; non-Windows plugin APIs leave a narrow external replacement race |
| Logs/crash dumps                  | Plaintext leakage                                  | Redacted structured logging, secret types, serialization tests            | OS crash capture can include memory                         |
| Replay attacks                    | Stale mutation accepted                            | Revisions, operation IDs, authenticated metadata, replay guards           | Offline devices need reconciliation                         |
| Rollback attacks                  | Old valid ciphertext presented as current          | Monotonic revisions/device-observed state                                 | Isolated device may not know newer state                    |
| Sync conflicts                    | Data loss/overwrite                                | Item-level revisions, explicit conflict policy, tombstones                | Human resolution may be needed                              |
| Emergency-state race              | Release after deny/revoke                          | Explicit state machine serialized in Durable Object; fail closed          | Control-plane failures can delay valid actions              |
| Attacker changes recipient        | Wrong recipient can decrypt grant                  | Bind recipient key fingerprint in authenticated grant metadata            | Compromised authorized device can approve malicious changes |
| Attacker adds device              | New device receives future key material            | Passkey auth, explicit authorization, notifications                       | Compromised account auth can still authorize a device       |
| Recovery-flow takeover            | Root access stolen                                 | High-entropy recovery secret, generation-fenced install/save, no server backdoor | Recovery-key theft is catastrophic; saved/printed copies can persist |
| Brute-force attempts              | Password/account guessing                          | Argon2id offline resistance; online rate limits/Turnstile                 | Weak passphrases remain weaker                              |
| Email compromise                  | Notifications/invitations intercepted              | Email contains no vault content; sensitive actions need stronger proof    | Social engineering risk remains                             |

## Phase 0 assumptions

- The first vertical slice is local-only and does not claim multi-device security.
- Local file attachments are encrypted before persistence with a fresh per-file key and authenticated 1 MiB chunks. The SQLite attachment tables expose only opaque attachment IDs, revisions, ciphertext envelopes, chunk indexes, and ciphertext; filenames and owner item IDs live inside authenticated encrypted manifests. The renderer receives metadata only after opening the owning record and never receives file bytes or attachment filesystem paths; the Rust Tauri command itself owns the native attachment picker/save dialog.
- Credential passwords, document numbers, and insurance policy numbers are excluded from list/search IPC responses. They are revealed to the renderer only after an explicit view/edit action while the vault is unlocked. Vehicle registration/VIN and possession serial numbers follow the same rule; item links (opaque IDs only) are visible in list responses so the UI can resolve titles on demand. Per-record legacy disposition is also excluded from list/search projections and is fetched/mutated only from the opened record using its exact revision.
- Credential password copy is separately backend-owned: the WebView supplies only record ID + exact revision, receives only the clear TTL, and is not granted generic clipboard read/write plugin permissions. The backend conditionally clears after 30 seconds, and on session invalidation, only after its SHA-256 ownership check. Windows holds the global clipboard lock across compare + clear; platforms without an atomic primitive use a best-effort immediate recheck and retain a narrow external-writer race. OS clipboard history or other software can retain earlier copies and remains outside Safeory's erasure guarantee.
- The emergency card (selected record IDs, contacts, instructions) is stored as one encrypted singleton record and is excluded from list/search/Trash IPC; titles resolve only through the narrow `get_item_titles` command while unlocked.
- The recovery-kit wrap, when installed, sits in the local database next to the passphrase wrap. Either secret alone unlocks the vault, so a saved or printed recovery key must be treated with the same care as the master passphrase. Recovery-key generation is session-bound; stale generated keys cannot be installed or saved after lock/re-unlock. The native Save flow writes only to a new user-selected file and removes partial output on failure/session invalidation; it does not expose the destination path through renderer IPC. Print is explicit and print-only, but OS print preview/spoolers, network printers, PDF printers, synced folders, and other software can retain plaintext. Replacing the live recovery wrap invalidates the old key for the current database and backups made afterward, but historical backups retain their captured recovery wrap; restoring one also restores that historical recovery configuration. Unlock-with-kit and unlock-with-passphrase errors are indistinguishable by design.
- The local Plan Test is deliberately narrower than future emergency release. Its readiness response contains only booleans about recovery configuration, Emergency Card completeness, and aggregate legacy-planning coverage; it does not return contact details, instructions, selected record identities, or which records have which legacy preference. Recovery-key self-test accepts the candidate only while the vault is already unlocked, zeroizes the Rust input, compares the recovered root to the authoritative in-memory root inside the crypto boundary, returns only match/mismatch, and does not replace the session or persist a verification flag. It does not simulate trusted-person sharing, waiting periods, timed release, or destruction. Legacy dispositions are planning intent only and do not themselves authorize release, verify death, or cause deletion.
- Human-readable JSON export and encrypted database backup are explicit user actions that write outside the app-data directory. The JSON export is plaintext by design, contains active record data including each record's legacy-planning disposition, excludes Trash/tombstones, and does not inline binary attachment contents; the UI labels that boundary. Encrypted backups use SQLite's snapshot API, are reopened and validated before publication, and preserve Trash, item and attachment tombstones, recovery configuration, object IDs/revisions, encrypted attachment manifests, all attachment chunks, and encrypted legacy dispositions.
- Backup restore never opens or migrates the user-selected backup in place. Safeory first copies it into app-data, validates SQLite integrity, schema compatibility, the supplied backup passphrase, every encrypted item lifecycle row, every attachment manifest, exact chunk sequence/count/size, and item-to-attachment ownership consistency, then replaces live encrypted tables inside one SQLite transaction. A failed validation leaves the current vault unchanged. Device-only lock settings are not restored from the vault backup.
- Moving an owning item to Trash retains its encrypted attachment rows so restore is lossless. Explicit attachment unlink and permanent item purge write authenticated attachment tombstones while deleting old chunk ciphertext in the same transaction; the tombstone does not retain the old file key. Attachment add/delete and parent-item reference updates are protected by revision CAS so stale renderer state cannot silently orphan or discard files.
- OS secure key storage and biometric convenience unlock are not yet implemented.
- The desktop flow provides explicit manual lock plus a configurable device-local inactivity timeout and optional lock-on-background policy. The timeout is enforced in Rust as well as the renderer. Locking invalidates both renderer and backend session generations before stale attachment work can commit or continue to another chunk, clears decrypted UI state, and drops the in-memory Rust vault session; process exit also drops it. Bulk attachment source/output I/O runs outside the vault-session mutex, so a slow file does not block the lock path.
- The SQLite file is treated as attacker-readable; secret-bearing columns remain authenticated ciphertext.
- An attacker controlling an already-unlocked process is outside the at-rest encryption boundary.
