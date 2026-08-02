FROM rust:1.90.0-bookworm@sha256:3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207 AS rust-builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY policy ./policy
COPY src ./src
RUN cargo build --locked --release --features nitro

FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /build/target/release/tee-google-key-updater /app/tee-google-key-updater
COPY --from=rust-builder /build/target/release/vsock-loopback /app/vsock-loopback
COPY vendor /tmp/vendor
RUN cd /tmp/vendor \
    && sha256sum --check SHA256SUMS \
    && install -m 0755 kmstool_enclave_cli /app/kmstool_enclave_cli \
    && install -m 0755 libnsm.so /usr/lib/libnsm.so \
    && rm -rf /tmp/vendor
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod 0555 /app/tee-google-key-updater /app/vsock-loopback /app/kmstool_enclave_cli /app/entrypoint.sh
ENV LD_LIBRARY_PATH=/usr/lib
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/tee-google-key-updater", "serve", "--port", "5000"]
