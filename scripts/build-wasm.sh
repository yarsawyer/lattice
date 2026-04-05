#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_HOME="${CARGO_HOME:-/tmp/lattice-cargo-home}"
TOOLS_ROOT="${TOOLS_ROOT:-/tmp/lattice-tools}"

mkdir -p "$ROOT/client/src/generated"

CARGO_HOME="$CARGO_HOME" cargo build \
  --manifest-path "$ROOT/crypto/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --release

"$TOOLS_ROOT/bin/wasm-bindgen" \
  --target web \
  --out-dir "$ROOT/client/src/generated" \
  "$ROOT/target/wasm32-unknown-unknown/release/lattice_crypto.wasm"
