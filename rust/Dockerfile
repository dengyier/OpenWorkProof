FROM rust:1.95.0-bookworm AS build

WORKDIR /src
COPY rust/Cargo.toml rust/Cargo.lock ./rust/
COPY rust/src/ ./rust/src/
COPY rust/tests/contracts.rs ./rust/tests/
COPY src/openworkproof/schemas/ ./src/openworkproof/schemas/
RUN cargo test --manifest-path rust/Cargo.toml --locked --all-targets \
    && cargo build --manifest-path rust/Cargo.toml --locked --release

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/dengyier/OpenWorkProof" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.modelcontextprotocol.server.name="io.github.dengyier/OpenWorkProof-Rust"
COPY --from=build /src/rust/target/release/owp-rust /usr/local/bin/owp-rust
COPY LICENSE /usr/share/doc/openworkproof-rust/LICENSE
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/owp-rust", "mcp"]
