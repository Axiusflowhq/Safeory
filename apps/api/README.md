# API

Cloudflare Workers API is intentionally deferred until the local vault and
recovery foundation are proven. When introduced, this surface must handle only
authentication/device coordination, opaque sync metadata, and policy workflows;
it must never receive vault plaintext or usable vault keys.
