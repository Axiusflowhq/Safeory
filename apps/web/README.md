# Safeory web vault

The static Next.js client runs the browser vault entirely in WASM and persists
only encrypted vault snapshots and wrapped browser credentials.

## Development sync enrollment

After unlocking the vault, open **Settings → Encrypted sync** and paste the
development `ACCOUNT_REGISTRATION_TOKEN` configured on the API. Enrollment uses
the same-origin `/api/` Caddy proxy, creates a durable browser device identity,
wraps the returned device bearer in IndexedDB, and publishes the initial private
space topology before starting encrypted-item sync. Use the Compose-served web
app (port `8080` by default) for this end-to-end path; the bare Next development
server does not provide Caddy's API proxy.

The registration token is held only long enough to submit account creation; it
is not written to browser storage. Local storage contains only the normalized
API URL plus account and device UUIDs. Production account enrollment still
requires confirmed Account Secret setup/publication UX and the reviewed identity
and device-approval flow described in the architecture roadmap.

While the vault is unlocked, sync runs after durable local changes, when the
browser comes online or returns to the foreground, on manual request, and every
30 seconds. Locking or closing the page stops this scheduler and clears in-memory
sync state.

## Commands

Run `bun run --filter @safeory/web typecheck`, `test`, `lint`, and `build` from
the repository root.
