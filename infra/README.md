# Self-hosted infrastructure

`docker-compose.yml` provides the local Safeory self-hosted stack:

- PostgreSQL for durable relational application data,
- Valkey for cache/ephemeral coordination,
- Garage for S3-compatible object storage, and
- Mailpit for local SMTP capture and inspection,
- `safeory-api` for server-visible coordination metadata and health checks, and
- the Safeory web app behind a same-origin `/api/*` reverse proxy.

Garage uses its supported single-node bootstrap flags to create the configured
development bucket and access key on first launch. Its metadata and object data
are stored in separate named Docker volumes. The single-node configuration has
no storage-node redundancy and should be expanded before production use.

The `api-migrate` one-shot service applies the current metadata-only PostgreSQL
migration before the API starts. All published ports bind to `127.0.0.1` by
default so they are not exposed on every host interface. The web service is the
normal local entry point at `http://127.0.0.1:8080`; the API is also published
on `127.0.0.1:8081` for local diagnostics.
