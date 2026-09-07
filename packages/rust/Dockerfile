# syntax=docker/dockerfile:1.7

FROM rust:1.89.0-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff AS builder

ARG TARGETARCH

RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends --yes ca-certificates git openssl pkg-config; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY Dockerfile ./Dockerfile
COPY src ./src
COPY vendor ./vendor
COPY docker/party-healthcheck.sh ./docker/party-healthcheck.sh

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=threshold-monero-target-${TARGETARCH},target=/build/target,sharing=locked \
    set -eux; \
    ./vendor/monero-oxide/verify-threshold-monero-sources.sh; \
    cargo build --locked --release --bin threshold-monero; \
    install --directory /out; \
    install --mode=0755 /build/target/release/threshold-monero /out/threshold-monero; \
    strip /out/threshold-monero; \
    : > /tmp/build-source-manifest; \
    find Cargo.toml Cargo.lock Dockerfile docker/party-healthcheck.sh src vendor -type f -print \
      | LC_ALL=C sort \
      | while IFS= read -r source_file; do \
          source_digest="$(openssl dgst -sha256 "${source_file}" | awk '{print $NF}')"; \
          printf '%s  %s\n' "${source_digest}" "${source_file}" \
            >> /tmp/build-source-manifest; \
        done; \
    openssl dgst -sha256 /tmp/build-source-manifest | awk '{print $NF}' \
      > /out/build-source-sha256; \
    test "$(wc -c < /out/build-source-sha256)" -eq 65

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

LABEL org.opencontainers.image.title="Threshold Monero signer" \
      org.opencontainers.image.description="AVSS, proactive resharing, and threshold Monero signing party" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends --yes ca-certificates curl tini; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 10002 threshold-monero; \
    useradd --uid 10002 --gid 10002 --home-dir /home/threshold-monero --create-home \
      --shell /usr/sbin/nologin threshold-monero; \
    install --directory --owner=threshold-monero --group=threshold-monero \
      /var/lib/threshold-monero

COPY --from=builder /out/threshold-monero /usr/local/bin/threshold-monero
COPY --from=builder --chmod=0444 /out/build-source-sha256 /build-source-sha256
COPY --chmod=0755 docker/party-healthcheck.sh /usr/local/bin/party-healthcheck

ENV RUST_LOG="threshold_monero=info,tower_http=info" \
    TM_STATE_DIR="/var/lib/threshold-monero"

USER 10002:10002
WORKDIR /home/threshold-monero

EXPOSE 8080/tcp 8443/udp
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/threshold-monero"]
CMD ["party"]
