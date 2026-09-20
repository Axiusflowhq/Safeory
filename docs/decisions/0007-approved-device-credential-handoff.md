# ADR 0007: Use Signed, Recipient-Encrypted Device Credential Handoffs

Date: 2026-09-20

## Status

Accepted and partially implemented. The cryptographic request/grant format and
durable pending-device API state machine are implemented; durable client-side
approval coordination, inventory confirmation, and product UX remain.

## Context

An additional device cannot use the first-device deployment registration token
without creating a different account. It must join an existing account only
after an active device explicitly approves it. The server-issued device bearer
is sufficient to access account ciphertext, so copying it in plaintext through
a QR code, clipboard, relay, email, or support channel would turn that transport
into an authentication authority.

The joining device already has separate X25519 encryption and Ed25519 signing
keys. The active device has the same two-key identity plus an authenticated
server session. The Account Secret and master passphrase remain the independent
factors that open the remotely stored root envelope; device approval must never
transport either factor.

## Decision

The joining device creates a V1 enrollment request containing:

- a random request UUID and the target account/device UUIDs;
- its X25519 and Ed25519 public keys;
- a fresh 256-bit challenge; and
- an Ed25519 signature over the complete versioned request transcript.

The active device verifies this self-signature before registering or approving
the supplied keys. The signature proves possession of the signing key and binds
the claimed recipient key; it does not, by itself, prove possession of the
X25519 private key.

After explicit approval, the active device creates a V1 grant that:

1. binds the complete request context, both device UUIDs, both devices' public
   keys, the format, and algorithm;
2. derives an encryption key from fresh-ephemeral-to-recipient and
   approver-static-to-recipient X25519 exchanges with HKDF-SHA-256;
3. encrypts only the bounded device credential package with
   XChaCha20-Poly1305; and
4. signs the grant context, nonce, ciphertext length, and ciphertext digest
   with the approver's Ed25519 key.

The joining device accepts a grant only when its locally retained request and
both local public keys match exactly, the approver signature verifies, and the
AEAD opens. Successfully decrypting and using the bearer demonstrates possession
of the joining X25519 private key. After authentication, the client must fetch
the bounded active-device inventory and require the grant's approver device ID
and both approver public keys to match an active device before persisting the
credential or importing the remote root.

The request and grant may cross an untrusted manual transport. Neither contains
the Account Secret, master passphrase, root key, or plaintext vault data. The
credential plaintext is bounded to 4 KiB and exists only transiently inside the
approver and joining clients.

## Pending activation state

Production server coordination uses a pending device rather than activating it
at approval time:

1. the approver durably prepares the encrypted grant and a verifier for its
   client-generated random bearer;
2. the authenticated approver creates or idempotently retries the pending
   device record using the request UUID;
3. the joining device decrypts the grant and presents that bearer to the
   activation endpoint;
4. activation atomically marks the device active and records a minimal security
   event; and
5. only active devices can use ordinary sync endpoints.

This ordering avoids an active-but-undeliverable credential after an approver
crash. Pending requests and grants are bounded, expire, and are consumed once.
Revocation and cancellation invalidate pending bearers. The existing immediate
`POST /v1/devices` development endpoint is not the production state machine.

## Security properties and limits

- Request substitution invalidates the joining-device signature.
- Grant or ciphertext substitution invalidates the approver signature and/or
  AEAD authentication.
- A relay learns device/account identifiers and public keys but not the bearer.
- A recipient cannot forge a grant from an active approver without that
  approver's Ed25519 key.
- A copied grant is useful only with the joining device's X25519 private key and
  is still bound to one account/device/request.
- Server inventory verification establishes that the signing approver was an
  active account device; a self-contained public key is not sufficient trust.
- Compromise of an unlocked approving client can authorize a malicious device.
- The server can deny, delay, or suppress enrollment, but cannot manufacture the
  Account Secret or decrypt the remote root envelope.

## Consequences

- `vault-sharing` owns the immutable request/grant wire format and cryptography.
- `vault-wasm` exposes only JSON packages and bounded transient credential bytes;
  browser key storage unwraps device private keys only for one operation.
- Web and extension coordinators must persist approval drafts before network
  mutation, consume joining requests/grants once, and verify server inventory
  before saving credentials.
- The API and database implement bounded pending-device creation, activation,
  cancellation, expiry, exact-input idempotency, approver-revocation
  invalidation, and minimal security-event state. Client approval drafts and UX
  still need to consume that state machine before the flow is production-ready.
