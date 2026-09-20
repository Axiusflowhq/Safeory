FROM rust:1.98.1-bookworm AS wasm-builder

RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-pack --version 0.15.0 --locked

WORKDIR /src
COPY . .
RUN wasm-pack build crates/vault-wasm \
    --target web \
    --release \
    --out-dir pkg \
    --locked

FROM node:24-bookworm-slim AS web-builder

COPY --from=oven/bun:1.4.1 /usr/local/bin/bun /usr/local/bin/bun

WORKDIR /src
COPY . .
COPY --from=wasm-builder /src/crates/vault-wasm/pkg ./crates/vault-wasm/pkg
RUN bun install --frozen-lockfile \
    && bun run --filter @safeory/web build

FROM caddy:2.11.4-alpine

COPY --from=web-builder /src/apps/web/out /srv
COPY --from=web-builder /src/apps/web/out/Caddyfile /etc/caddy/Caddyfile
RUN rm /srv/Caddyfile

EXPOSE 8080
