# Safeory Plan — V1 Local Platform vs What Comes Next

Source vision: Private Life OS — organize life, own possessions, continue through
emergencies, protect with zero-knowledge encryption. Trustworthy is the baseline;
the Ownership Wallet + Continuity Engine + real privacy are the differentiators.

Rule: cloud integration starts only after the local platform below is stable.

## V1 scope (the 23 launch items) — status

### PRIVATE LIFE
| # | Item | Status |
|---|------|--------|
| 1 | Documents | ✅ Done — encrypted metadata (number masked), search, trash/restore |
| 2 | Important records | ✅ Done — secure notes, credentials (masked + generator + guarded 30s clipboard copy) |
| 3 | Property | ✅ Done — masked address/reference, ownership validation |
| 4 | Insurance | ✅ Done — masked policy number, renewal feeds Today |
| 5 | Vehicles | ✅ Done — make/model/year/renewal, reg/VIN masked, renewal feeds Today |
| 6 | Valuable possessions | ✅ Done — brand/serial/purchase/warranty, serial masked, warranty feeds Today |

### OWNERSHIP
| # | Item | Status |
|---|------|--------|
| 7 | Receipts | ✅ Done — dedicated encrypted receipts, masked references, links/attachments, return/refund tracking + Today deadlines |
| 8 | Warranty tracking | ✅ Done — `warranty_expiry` + Today alerts |
| 9 | Expiry/renewal reminders | ✅ Done — tested deadlines engine in `vault-core`, Today panel over IPC |

### PEOPLE
| # | Item | Status |
|---|------|--------|
| 10 | Trusted people | 🟡 Partial — emergency contacts live in the Emergency Card; no trust graph, no device keys UX |
| 11 | Granular permissions | 🟡 Crypto/policy core only — `vault-emergency` evaluates View/Edit/Download/Share/Manage; no persistence in payloads, no UX |

### PLAN
| # | Item | Status |
|---|------|--------|
| 12 | Emergency access | 🟡 Partial — Emergency Card (records + contacts + instructions) works; timed release does not |
| 13 | Waiting periods | 🟡 Policy core only — 1h/24h/7d/custom evaluated locally; no enforcement timer, no server coordinator |
| 14 | Selected legacy access | 🟡 Local planning done — each active record can be marked Unspecified/Selected for legacy/Private forever/Destroy on death; this is encrypted planning metadata only, with no trusted-person release or automatic deletion enforcement yet |
| 15 | "If something happens to me" | 🟡 Partial — card + instructions + kit cover the single-device case |
| 16 | Plan test | ✅ Done (local) — checks Emergency Card completeness + verifies the saved recovery key against the current vault; does not simulate trusted-person/timed-release flows |

### PRIVACY
| # | Item | Status |
|---|------|--------|
| 17 | Client-side encryption | ✅ Done — XChaCha20-Poly1305, per-item keys, Argon2id KEK |
| 18 | Zero-knowledge server | ⏸️ N/A yet — no server exists; architecture doc'd (`docs/architecture/overview.md`) |
| 19 | Local encrypted vault | ✅ Done — SQLite ciphertext-only, rollback-journal tested |
| 20 | E2EE sharing | 🟡 Crypto layer done (`vault-sharing`: X25519 ephemeral-static, fingerprint-bound, purpose-separated); no transport |
| 21 | Recovery kit | ✅ Done — save/print, install/confirm, live-key replacement, unlock-with-kit, recovery-authenticated backup restore with new passphrase, 2-of-3 social recovery crypto + e2e test |
| 22 | Device management | 🟡 Partial — auto-lock, lock-on-background, settings; no multi-device, no revoke, no travel mode |
| 23 | Portable export | ✅ Done — readable JSON + encrypted DB backup to user-chosen paths |

## What is implemented but not wired (crypto-ready, no IPC/UI)
- `vault-sharing`: seal/open envelopes for item keys and recovery shares.
- `vault-emergency`: policy evaluation, Shamir threshold (`blahaj`, RUSTSEC-2024-0398 fix), sealed share envelopes, full no-vendor recovery path.
- Compartment key hierarchy: spec'd, not coded (`safeory:v1:compartment-wrap`).

## Backlog — ordered, post-V1
1. Grant persistence inside item payloads + trusted-person management UX.
2. Emergency timed-release state machine (local simulation first, Durable Object later).
3. Enforce legacy/private-forever/destruction intent through trusted-person + emergency-release state once that machinery exists.
4. Plan test (simulation) + preparedness score beyond today's local readiness checks.
5. Sync: device auth, D1 metadata, R2 blobs, queues/notifications.
6. OS keystore + biometric unlock; passkeys/TOTP.
7. Expanded home inventory and account-closure automation. Local encrypted subscription tracking and credential closure planning are done; Safeory still does not contact providers, process subscription payments, cancel subscriptions, or close accounts automatically.
8. Email import, browser capture, mobile scanner, private-AI modes (local-first per spec).
9. Version-history restore/rollback and richer audit metadata; bounded encrypted browse-only history is implemented locally (20 prior revisions/item), but restoring an old snapshot is intentionally deferred because historical attachment references may no longer have live attachment data. Family space and secure links remain future work.

## Non-goals (explicit)
Password autofill, banking/investment aggregation, resale marketplace, whole-vault
cloud AI, ads/data business of any kind, company-side decryption — ever.

## Verification gates (must stay green)
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `cargo audit`, `cargo deny check advisories bans licenses sources`,
`pnpm typecheck`, `pnpm lint`, `pnpm build`. Dependency additions follow the review
rule in `docs/security/dependency-risk-register.md` — deny failures block, no silent ignores.
