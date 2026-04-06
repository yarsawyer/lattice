# Stage 1: Build WASM bindings from crypto crate
FROM rust:1.88-bookworm AS wasm
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.117 --locked
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crypto/ crypto/
COPY server/ server/
RUN cargo build --manifest-path crypto/Cargo.toml --target wasm32-unknown-unknown --release
RUN wasm-bindgen --target web --out-dir /wasm-out \
    target/wasm32-unknown-unknown/release/lattice_crypto.wasm

# Stage 2: Build client
FROM node:22-bookworm-slim AS client
WORKDIR /build/client
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client/ .
COPY --from=wasm /wasm-out/ src/generated/
RUN npm run build

# Stage 3: Build server
FROM rust:1.88-bookworm AS server
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crypto/ crypto/
COPY server/ server/
RUN cargo build --release -p lattice-server

# Stage 4: Minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system --gid 1001 lattice && \
    adduser --system --uid 1001 --ingroup lattice lattice
WORKDIR /app
COPY --from=server --chown=lattice:lattice /build/target/release/lattice-server .
COPY --from=client --chown=lattice:lattice /build/client/dist/ client/dist/
USER lattice
EXPOSE 3000
ENV LATTICE_HOST=0.0.0.0
CMD ["./lattice-server"]
