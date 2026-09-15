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
| Clipboard leakage                 | Secret retained outside app                        | No credential copy action in Phase 0; timed clear required before adding  | OS clipboard managers may retain data once copy is enabled  |
| Logs/crash dumps                  | Plaintext leakage                                  | Redacted structured logging, secret types, serialization tests            | OS crash capture can include memory                         |
| Replay attacks                    | Stale mutation accepted                            | Revisions, operation IDs, authenticated metadata, replay guards           | Offline devices need reconciliation                         |
| Rollback attacks                  | Old valid ciphertext presented as current          | Monotonic revisions/device-observed state                                 | Isolated device may not know newer state                    |
| Sync conflicts                    | Data loss/overwrite                                | Item-level revisions, explicit conflict policy, tombstones                | Human resolution may be needed                              |
| Emergency-state race              | Release after deny/revoke                          | Explicit state machine serialized in Durable Object; fail closed          | Control-plane failures can delay valid actions              |
| Attacker changes recipient        | Wrong recipient can decrypt grant                  | Bind recipient key fingerprint in authenticated grant metadata            | Compromised authorized device can approve malicious changes |
| Attacker adds device              | New device receives future key material            | Passkey auth, explicit authorization, notifications                       | Compromised account auth can still authorize a device       |
| Recovery-flow takeover            | Root access stolen                                 | High-entropy recovery secret, rate limits, no server backdoor             | Recovery secret theft is catastrophic                       |
| Brute-force attempts              | Password/account guessing                          | Argon2id offline resistance; online rate limits/Turnstile                 | Weak passphrases remain weaker                              |
| Email compromise                  | Notifications/invitations intercepted              | Email contains no vault content; sensitive actions need stronger proof    | Social engineering risk remains                             |

## Phase 0 assumptions

- The first vertical slice is local-only and does not claim multi-device security.
- Document records in Phase 0 contain encrypted metadata only. File attachments remain out of scope until their chunking/key/nonce framing is implemented and reviewed.
- Credential passwords, document numbers, and insurance policy numbers are excluded from list/search IPC responses. They are revealed to the renderer only after an explicit view/edit action while the vault is unlocked. Vehicle registration/VIN and possession serial numbers follow the same rule; item links (opaque IDs only) are visible in list responses so the UI can resolve titles on demand.
- The emergency card (selected record IDs, contacts, instructions) is stored as one encrypted singleton record and is excluded from list/search/Trash IPC; titles resolve only through the narrow `get_item_titles` command while unlocked.
- The recovery-kit wrap, when installed, sits in the local database next to the passphrase wrap. Either secret alone unlocks the vault, so the printed kit secret must be treated with the same care as the master passphrase. Unlock-with-kit and unlock-with-passphrase errors are indistinguishable by design.
- Human-readable JSON export and database-file backup are explicit user actions that write outside the app-data directory. The JSON export is plaintext by design (it must be readable without Safeory); the UI warns before writing, and export files are never created automatically.
- OS secure key storage and biometric convenience unlock are not yet implemented.
- The desktop flow provides explicit manual lock and a 10-minute inactivity lock. Both invalidate the renderer session generation before clearing decrypted UI state and dropping the in-memory Rust vault session; process exit also drops it.
- The SQLite file is treated as attacker-readable; secret-bearing columns remain authenticated ciphertext.
- An attacker controlling an already-unlocked process is outside the at-rest encryption boundary.
