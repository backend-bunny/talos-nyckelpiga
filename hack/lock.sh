#!/usr/bin/env bash
# Regenerate apko.lock.json against today's Wolfi index. The melange package
# is built first so apko can resolve its dependencies, then dropped from the
# committed lock (see hack/lockfile.py).
# Usage: hack/lock.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

build_package "$tmp" "$tmp/melange.rsa.pub" notest
fresh_lock "$tmp/melange.rsa.pub" "$tmp/fresh.lock.json"
python3 hack/lockfile.py strip "$tmp/fresh.lock.json" apko.lock.json
echo "wrote apko.lock.json"
