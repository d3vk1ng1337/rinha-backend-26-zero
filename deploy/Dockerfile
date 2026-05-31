# Build: compila o servidor + converter e gera o índice (build-time, amd64).
FROM rust:1-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p zero-server -p zero-convert

# Gera o índice a partir das referências (presentes no contexto de build).
COPY data/references.json.gz /tmp/references.json.gz
RUN /app/target/release/zero-convert /tmp/references.json.gz /index.bin

# Runtime: só o binário + índice.
FROM debian:trixie-slim
COPY --from=build /app/target/release/zero-server /usr/local/bin/zero-server
COPY --from=build /index.bin /index/index.bin
ENTRYPOINT ["zero-server"]
