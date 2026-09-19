# Threat Model

Status: browser/WASM + extension + self-hosted API baseline. Update this document before each security-sensitive feature ships.

## Assets

- Vault plaintext, attachments, credentials, recovery codes, and emergency instructions.
- AccountRootKey and derived/wrapped item keys.
- Device private keys and recovery-key material.
- Trusted-person authorization and emergency-grant state.
- Integrity of revisions, tombstones, sync state, and device authorization.

## Trust boundaries

1. Rust cryptographic/domain code and the `vault-wasm` boundary.
2. Web-app JavaScript/DOM and WASM linear memory.
3. Browser IndexedDB ciphertext persistence.
4. Extension background worker, trusted extension pages, browser-managed storage, and untrusted page content scripts.
5. Browser/OS clipboard, file-download, print, and process-memory boundaries.
6. Network boundary.
7. Self-hosted API, PostgreSQL, S3-compatible object storage, Valkey, workers, and SMTP.
8. Trusted recipient devices.

## Threat register

| Threat | Consequence | Primary mitigation | Residual risk |
| --- | --- | --- | --- |
| Stolen PostgreSQL database | Account/security metadata exposed | Minimize plaintext metadata; opaque IDs; E2EE vault objects | Metadata correlation remains visible |
| Stolen object-storage bucket | Ciphertext exfiltration/offline attack | Per-item/file keys, AEAD, strong root-key wrapping | Weak passphrases still weaken offline resistance |
| Malicious backend administrator | Unauthorized metadata actions or early policy transitions | Backend never receives usable vault keys; strict auth/audit | Admin can deny service or release encrypted capsules early |
| Backend compromise | Modification/replay/availability attacks | Authenticated envelopes, revisions, device auth, replay checks | Availability cannot be guaranteed |
| Compromised Valkey/worker queue | Retry abuse, rate-limit bypass, duplicated jobs | Durable authorization stays in PostgreSQL; idempotent work | Queue compromise can delay or amplify work |
| Proxy/application log exposure | Metadata, bearer token, or ciphertext copied into logs | No request-body/auth-secret logging; structured redaction | Network/account metadata remains observable to operator |
| Compromised user passphrase | Root key can be unwrapped with the stored wrap | Argon2id, strong UX, rewrap on change | Known passphrase plus wrap material is catastrophic |
| Stolen or compromised device | Plaintext/key theft while unlocked | Encrypted local persistence, explicit lock, minimal redacted projections | Malware can inspect process memory/screens while unlocked |
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
| Emergency-state race | Release after deny/revoke | PostgreSQL state machine with revision/idempotency checks; fail closed | Control-plane failure can delay valid actions |
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
- The web and extension currently maintain separate local ciphertext stores. Until sync convergence ships, neither surface may imply records automatically appear in the other.
- Browser attachment/export flows must use explicit user-mediated browser APIs and keep encryption/decryption in the client security boundary. Native SQLite attachment/backup utilities remain library/test capabilities, not a shipping client surface.

## Extension assumptions

- Only the extension background worker owns the unlocked `WasmVault`. Content scripts receive neither keys nor a whole decrypted vault.
- Credential summaries are fetched only after a trusted click on the Safeory affordance. The background derives origin from `MessageSender`, requires exact normalized HTTP(S) scheme/host/effective-port matching, rate-limits per tab+origin, and issues a short-lived one-shot fill authorization consumed before decrypting a selected credential.
- Extension-page privileged commands require a same-extension page sender without a tab sender. Content-script and extension-page message surfaces use separate checks.
- Cross-origin frames are not treated as the top-level origin. Autofill must not cross origin boundaries by caller assertion.
- Password copy currently performs best-effort delayed compare-and-clear from the popup. Closing the popup or losing clipboard permission can prevent cleanup; OS clipboard history/sync is outside Safeory's erasure guarantee.

## Server assumptions

- The API never receives usable vault decryption keys or vault plaintext.
- PostgreSQL is authoritative for server-visible account/device/revision/idempotency/policy state. Valkey is ephemeral and cannot authorize durable security transitions by itself.
- Object storage contains opaque encrypted objects. Cross-account object access fails closed and server logs must not contain bearer tokens or object bodies.
- Email contains notifications/invitations only, never vault plaintext or decryption material.
