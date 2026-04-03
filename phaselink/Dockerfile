# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.93-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev curl && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create data directory for SQLite DB
RUN mkdir -p /data

WORKDIR /data

VOLUME /data

COPY --from=builder /app/target/release/zeeble-server /usr/local/bin/zeeble-server

CMD ["zeeble-server"]

EXPOSE 4000
