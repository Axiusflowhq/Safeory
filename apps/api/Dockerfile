FROM rust:1.98.1-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --locked --release -p safeory-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 safeory \
    && useradd --uid 10001 --gid safeory --no-create-home --shell /usr/sbin/nologin safeory
COPY --from=builder /build/target/release/safeory-api /usr/local/bin/safeory-api

USER safeory
EXPOSE 8080
ENV BIND_ADDR=0.0.0.0:8080
ENTRYPOINT ["/usr/local/bin/safeory-api"]
