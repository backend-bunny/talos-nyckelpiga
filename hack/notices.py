#!/usr/bin/env python3
"""License notices for the Rust crates linked into the binary.

The apko SBOM lists APKs only, so the crates inside talos-nyckelpiga are not
in it (cargo-auditable embeds their names and versions in the binary for
scanners). This writes, from `cargo metadata`, every crate reachable from the
binary through normal (non-build, non-dev) dependencies on the image's
target, with its declared license and the license/notice files it ships.
Published as a cosign attestation next to the SBOM, like
container-dropshipping's notices attestation.

  notices.py OUT_JSON OUT_MD
"""

import json
import pathlib
import subprocess
import sys

TARGET = "x86_64-unknown-linux-musl"
NOTICE_PREFIXES = ("license", "licence", "copying", "notice", "unlicense", "copyright")
MAX_FILE = 256 * 1024


def metadata():
    subprocess.run(["cargo", "fetch", "--locked", "--target", TARGET], check=True)
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def linked_packages(meta):
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["resolve"]["root"]
    seen, todo = {root}, [root]
    while todo:
        for dep in nodes[todo.pop()]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]) and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                todo.append(dep["pkg"])
    return [p for p in meta["packages"] if p["id"] in seen]


def notice_files(pkg):
    root = pathlib.Path(pkg["manifest_path"]).parent
    files = {}
    for f in sorted(root.iterdir()):
        if f.is_file() and f.name.lower().startswith(NOTICE_PREFIXES):
            files[f.name] = f.read_bytes()[:MAX_FILE].decode("utf-8", "replace")
    if pkg.get("license_file"):
        f = root / pkg["license_file"]
        if f.is_file():
            files[pkg["license_file"]] = f.read_text("utf-8", "replace")[:MAX_FILE]
    return files


def main(out_json, out_md):
    meta = metadata()
    crates = []
    for pkg in sorted(linked_packages(meta), key=lambda p: (p["name"], p["version"])):
        crates.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "license": pkg.get("license") or "NOASSERTION",
                "source": pkg.get("source") or "this repository",
                "repository": pkg.get("repository"),
                "files": notice_files(pkg),
            }
        )
    missing = [c["name"] for c in crates if not c["files"] and c["source"] != "this repository"]
    with open(out_json, "w") as f:
        json.dump({"crates": crates}, f, indent=2)
        f.write("\n")
    with open(out_md, "w") as f:
        f.write(f"{len(crates)} crates in the binary.\n\n| Crate | Version | License | Notice files |\n|---|---|---|---|\n")
        for c in crates:
            f.write(f"| {c['name']} | {c['version']} | {c['license']} | {', '.join(c['files']) or '—'} |\n")
        if missing:
            f.write(f"\nNo license file shipped (declared license only): {', '.join(missing)}\n")
    print(f"notices: {len(crates)} crates, {len(missing)} without license files")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])
