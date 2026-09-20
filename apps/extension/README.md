# Safeory browser extension

The MV3 extension keeps the unlocked vault and usable key inside its background
service worker. Its durable vault snapshot contains ciphertext only.

## Development encrypted sync

Run the local Compose stack, unlock the extension, and use the **Encrypted
sync** card in the popup. The default API URL is the Caddy-served development
endpoint at `http://127.0.0.1:8080/api/`. Paste the configured
`ACCOUNT_REGISTRATION_TOKEN` to create a development account and device.

The registration token is used only by that account-creation request. It is not
stored. The returned device bearer is encrypted under a non-extractable
IndexedDB key; `chrome.storage.local` receives only the API URL and account and
device UUIDs. HTTPS endpoints require an explicit, origin-scoped browser
permission when enrollment is submitted.

While the background vault remains unlocked, the extension pulls and pushes
opaque encrypted records after a durable local credential change, on manual
request, after unlock/reconnect, and on a one-minute browser alarm. Sync remote
acceptance runs through the same serialized snapshot queue as local mutation
and uses exact-ciphertext compare-and-swap. Locking aborts active network work
and clears in-memory sync state. If the MV3 worker is reclaimed, reopen the
popup and unlock again; usable vault keys are intentionally never persisted.

Development enrollment currently creates an independent single-owner account.
Joining the same account as the web app awaits the reviewed production Account
Secret/new-device enrollment flow.

## Commands

Run `bun run --filter @safeory/extension typecheck`, `test`, `lint`, and `build`
from the repository root.
