# Safeory web vault

The static Next.js client runs the browser vault entirely in WASM and persists
only encrypted vault snapshots and wrapped browser credentials.

## Development sync enrollment

After unlocking the vault, open **Settings → Encrypted sync** and paste the
development `ACCOUNT_REGISTRATION_TOKEN` configured on the API. The setup flow
re-authenticates the local vault, generates and confirms a checksummed Account
Secret, durably queues its account-bound encrypted root envelope, and publishes
that envelope before the initial private-space topology and encrypted-item sync.
Enrollment uses the same-origin `/api/` Caddy proxy, creates a durable browser
device identity, and wraps the returned device bearer in IndexedDB. Use the
Compose-served web app (port `8080` by default) for this end-to-end path; the
bare Next development server does not provide Caddy's API proxy.

The registration token, master passphrase, and Account Secret are held only for
the enrollment attempt and are not written to browser storage. The Account
Secret is never sent to the API; only its encrypted root envelope is published.
Local storage contains only the normalized API URL plus account and device UUIDs.
This remains a development-token flow: production account identity, approved
new-device enrollment, hosted recovery, and external review remain roadmap work.

While the vault is unlocked, sync runs after durable local changes, when the
browser comes online or returns to the foreground, on manual request, and every
30 seconds. Locking or closing the page stops this scheduler and clears in-memory
sync state.

## Commands

Run `bun run --filter @safeory/web typecheck`, `test`, `lint`, and `build` from
the repository root.
