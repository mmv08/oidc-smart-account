FROM rust:1.90.0-bookworm@sha256:3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin tee-updater

FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e
COPY --from=build /build/target/release/tee-updater /app/tee-updater
CMD ["/app/tee-updater", "serve"]
