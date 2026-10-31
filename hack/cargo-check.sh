#!/usr/bin/env bash
# Rust checks, as CI runs them: fmt, clippy -D warnings, unit and integration
# tests. The integration tests need `bao` (devbox provides it) and fail
# instead of skipping when it is missing.
# Usage: hack/cargo-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
NYCKELPIGA_REQUIRE_BAO=1 cargo test --locked
