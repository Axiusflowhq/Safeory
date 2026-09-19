# Safeory API

`safeory-api` is the first Docker-oriented self-hosted HTTP service. It owns
server-visible coordination metadata only. Vault plaintext, passphrases,
recovery secrets, usable vault keys, and decryption logic do not belong here.

## Configuration

The service reads configuration only from environment variables:

- `DATABASE_URL` — PostgreSQL connection URL.
- `VALKEY_URL` — Valkey connection URL using the Redis protocol.
- `BIND_ADDR` — socket address to listen on, for example `0.0.0.0:8080`.
- `RUST_LOG` — optional tracing filter.

## Health endpoints

- `GET /health/live` checks only that the HTTP process is running.
- `GET /health/ready` performs bounded live checks against PostgreSQL and
  Valkey. It returns HTTP 503 until both dependencies respond.

## Database

Migrations live in `apps/api/migrations`. The initial migration creates only
opaque account, device, and ciphertext-object metadata. Applying migrations is
an explicit deployment step; `docker-compose.yml` performs it through the
one-shot `api-migrate` service before starting the API. The API process itself
still does not require database connectivity in order to start serving process
liveness.

Authentication and sync payload upload are intentionally outside this slice.
