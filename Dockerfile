# syntax=docker/dockerfile:1.7
# ---------- Build stage ----------------------------------------------------
FROM rust:1-bookworm AS build

# protobuf-compiler is required by tonic/prost-build at compile time.
# pkg-config + libssl-dev for the few crates that still link against system
# OpenSSL (reqwest defaults to rustls, but some optional deps use native-tls).
RUN apt-get update -qq \
 && apt-get install -qq -y --no-install-recommends \
      protobuf-compiler \
      libprotobuf-dev \
      pkg-config \
      libssl-dev \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifest first so the dependency layer caches across source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY proto/ ./proto/

# Build a statically-linkable release binary (glibc — matches bookworm runtime).
# Offline once deps are downloaded the first time.
RUN cargo build --release --bin kxn \
 && strip target/release/kxn

# ---------- Runtime stage --------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates so reqwest can verify TLS (GitHub releases, Grafana Cloud, etc.)
# tini for proper PID-1 signal handling in K8s.
# Tools that kxn calls internally are covered by its Rust deps — nothing else
# needs to be installed at runtime.
RUN apt-get update -qq \
 && apt-get install -qq -y --no-install-recommends \
      ca-certificates \
      tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1000 kxn \
 && useradd  --system --uid 1000 --gid kxn --home /home/kxn --shell /usr/sbin/nologin --create-home kxn

COPY --from=build /build/target/release/kxn /usr/local/bin/kxn

USER kxn:kxn
WORKDIR /home/kxn

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/kxn"]
CMD ["--help"]
