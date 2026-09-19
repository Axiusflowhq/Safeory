# Historical Cloudflare planning file

Cloudflare is no longer Safeory's production hosting target. This path is kept
only so old links do not silently point to missing documentation.

The production architecture is AWS and is defined in:

- `docs/architecture/aws.md` — production topology, security boundary, cost
  posture, scaling path, backup/recovery, and launch gate;
- `docs/architecture/overview.md` — product-wide dependency and trust boundary;
- `docs/security/server-visible-metadata.md` — permitted backend plaintext.

`docker-compose.yml` remains the local development/integration environment.
