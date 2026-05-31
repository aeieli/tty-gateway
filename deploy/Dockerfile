# syntax=docker/dockerfile:1

# --- Build stage ---
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin shark-gateway

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin shark
COPY --from=build /src/target/release/shark-gateway /usr/local/bin/shark-gateway
USER shark
# QUIC is UDP.
EXPOSE 4433/udp
ENTRYPOINT ["shark-gateway", "--config", "/etc/shark-gateway/shark-gateway.toml"]
