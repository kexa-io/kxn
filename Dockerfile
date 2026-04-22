# syntax=docker/dockerfile:1.7
# ---------- Build stage ----------------------------------------------------
# Pin to a specific minor version so builds are reproducible — floating tags
# like rust:1 silently update and can break a build months later.
FROM rust:1.95-bookworm AS build

# protobuf-compiler is required by tonic/prost-build at compile time.
# pkg-config + libssl-dev for crates that link against system OpenSSL
# (native-tls, async-ssh2-tokio, mongodb, …).
RUN apt-get update -qq \
 && apt-get install -qq -y --no-install-recommends \
      protobuf-compiler \
      libprotobuf-dev \
      pkg-config \
      libssl-dev \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ---------------------------------------------------------------------------
# Dependency-caching layer
#
# Strategy: copy only manifests first, create minimal stub source files, run
# cargo build --release so that all dependency crates are compiled and cached
# in a Docker layer, then replace the stubs with the real source and do the
# final build.  Without the dummy compile step the layer is never reused
# because cargo will not download/compile deps until it has source to compile
# against.
# ---------------------------------------------------------------------------

# 1. Copy workspace manifest + per-crate manifests (no source yet).
COPY Cargo.toml Cargo.lock ./
COPY crates/kxn-core/Cargo.toml    crates/kxn-core/Cargo.toml
COPY crates/kxn-rules/Cargo.toml   crates/kxn-rules/Cargo.toml
COPY crates/kxn-providers/Cargo.toml crates/kxn-providers/Cargo.toml
COPY crates/kxn-mcp/Cargo.toml     crates/kxn-mcp/Cargo.toml
COPY crates/kxn-cli/Cargo.toml     crates/kxn-cli/Cargo.toml

# kxn-providers has a build.rs that invokes tonic-build; proto files are
# needed even during the dummy compile so prost-build can generate stubs.
COPY proto/ ./proto/

# 2. Create minimal stub sources for every crate.
#    - Library crates get src/lib.rs
#    - kxn-cli is the only [[bin]] crate and gets src/main.rs
RUN mkdir -p \
      crates/kxn-core/src \
      crates/kxn-rules/src \
      crates/kxn-providers/src \
      crates/kxn-mcp/src \
      crates/kxn-cli/src \
 && touch \
      crates/kxn-core/src/lib.rs \
      crates/kxn-rules/src/lib.rs \
      crates/kxn-providers/src/lib.rs \
      crates/kxn-mcp/src/lib.rs \
 && echo 'fn main() {}' > crates/kxn-cli/src/main.rs

# kxn-providers also needs its build.rs so cargo can discover the codegen step.
COPY crates/kxn-providers/build.rs crates/kxn-providers/build.rs

# 3. Compile deps only (stubs produce no real code — this layer is reused
#    whenever manifests + Cargo.lock are unchanged).
RUN cargo build --release --bin kxn

# 4. Remove the stub artifacts so the real build starts from a clean slate.
RUN rm -rf \
      crates/kxn-core/src \
      crates/kxn-rules/src \
      crates/kxn-providers/src \
      crates/kxn-mcp/src \
      crates/kxn-cli/src \
 && find target/release -name "*.d" -delete

# 5. Copy the real source and run the final build.
COPY crates/ ./crates/

# Bump mtime of every real .rs file so it is newer than the stub rlibs from
# step 3. Without this, COPY preserves the host mtime (often older than the
# stub build time), cargo sees "source older than output" and reuses the stub
# artifacts — the final binary ends up as the stub `fn main() {}`.
RUN find crates -name '*.rs' -exec touch {} +

RUN cargo build --release --bin kxn \
 && strip target/release/kxn

# ---------- Runtime stage --------------------------------------------------
# Pin to a specific digest-stable tag so the runtime environment is
# reproducible (bookworm-slim receives security patches in-place, which can
# occasionally change ABI or package layout without a tag bump).
FROM debian:bookworm-20250428-slim AS runtime

# ca-certificates so TLS verification works for outbound connections.
# tini for proper PID-1 signal handling in containers (SIGTERM propagation).
# No libssl is needed at runtime: the binary links native-tls which bundles
# OpenSSL at compile time (or uses rustls where available) — no shared .so.
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
