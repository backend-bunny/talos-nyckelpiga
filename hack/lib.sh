# Shared by the hack/*.sh scripts (sourced; cwd is the repo root).

# Image architectures. Adding aarch64: append it here and to apko.yaml's
# `archs`, and build the melange package for it (see build_package).
ARCHS=(x86_64)
REGISTRY=${REGISTRY:-ghcr.io/backend-bunny}
IMAGE=$REGISTRY/talos-nyckelpiga
MELANGE_RUNNER=${MELANGE_RUNNER:-bubblewrap}
# Download caches reused across builds (CI restores/saves this dir): the
# cargo registry and target dir at /var/cache/melange inside the build, and
# the Wolfi APKs for melange's build environment.
CACHE_DIR=${CACHE_DIR:-.cache}
# Recorded as the recipe source in melange's SBOM.
REPO_URL=https://github.com/backend-bunny/talos-nyckelpiga

# Reproducible timestamps for melange and apko: the commit being built.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH

# package.version from melange.yaml (equal to Cargo.toml's, see check-version.sh).
version() {
  awk '/^  version:/ { gsub(/"/, "", $2); print $2; exit }' melange.yaml
}

# The apko argument adding the version as an OCI annotation (and label).
version_annotation() {
  printf '%s\n' --annotations "org.opencontainers.image.version:$(version)"
}

# Copy the source melange builds into $1: committed and untracked files that
# aren't ignored (so no target/, out/ or .cache/). In CI that is the commit.
# Regular files and symlinks only (sandboxes can leave device nodes around).
export_source() {
  local dest=${1:?} f
  mkdir -p "$dest"
  git ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' f; do
        [[ -f $f || -L $f ]] && printf '%s\0' "$f"
      done \
    | tar --null --files-from=- --create --file=- \
    | tar --extract --file=- --directory="$dest"
}

# Vendor every crate in Cargo.lock into $1/vendor and point cargo at it, so
# the melange build runs offline (hermetic; cargo still verifies each crate
# against Cargo.lock's checksums). Downloads land in the host's cargo cache.
vendor_crates() {
  local src=${1:?}
  mkdir -p "$src/.cargo"
  # Relative path: the config must work wherever melange mounts the source.
  (cd "$src" && cargo vendor --locked --versioned-dirs vendor) > "$src/.cargo/config.toml"
  cat >> "$src/.cargo/config.toml" <<'TOML'

[net]
offline = true
TOML
}

# Build (and, unless $3 is "notest", test) the melange package into
# ./packages, signed with a throwaway key. The private key is deleted as soon
# as the APKs are signed; its public half is copied to $2 for apko. Key
# generation and the source export happen in $1, a temp dir the caller
# removes.
build_package() {
  local tmp=$1 pub=$2 mode=${3:-test} arch
  rm -rf packages
  local key=$tmp/keygen src=$tmp/src
  mkdir -p "$key"
  (cd "$key" && melange keygen >/dev/null)
  export_source "$src"
  vendor_crates "$src"
  mkdir -p "$CACHE_DIR/melange" "$CACHE_DIR/apk"
  for arch in "${ARCHS[@]}"; do
    melange build melange.yaml \
      --arch "$arch" --runner "$MELANGE_RUNNER" --source-dir "$src" \
      --cache-dir "$CACHE_DIR/melange" --apk-cache-dir "$CACHE_DIR/apk" \
      --git-repo-url "$REPO_URL" --namespace backend-bunny \
      --signing-key "$key/melange.rsa" --out-dir packages
  done
  cp "$key/melange.rsa.pub" "$pub"
  rm -rf "$key"

  if [[ $mode != notest ]]; then
    for arch in "${ARCHS[@]}"; do
      melange test melange.yaml \
        --arch "$arch" --runner "$MELANGE_RUNNER" \
        --repository-append ./packages --keyring-append "$pub" \
        --repository-append https://packages.wolfi.dev/os \
        --keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    done
  fi
}

# Comma-separated --arch value for apko.
apko_archs() {
  local IFS=,
  echo "${ARCHS[*]}"
}

# `apko lock` against the current ./packages, written to $2.
fresh_lock() {
  local pub=$1 out=$2
  apko lock apko.yaml --arch "$(apko_archs)" --keyring-append "$pub" --output "$out"
}
