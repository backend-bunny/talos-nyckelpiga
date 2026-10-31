#!/usr/bin/env python3
"""Split apko lockfiles into a committed Wolfi part and a per-build local part.

`apko lock` records every package with its signature/control/data checksums,
and `apko build --lockfile` enforces the control hash. For packages melange
builds here (`@local`), that hash changes on every commit (melange records the
git commit in .PKGINFO), so locking them would make the lock stale on every
build. We therefore commit only the Wolfi packages and, at build time, merge
them with fresh entries for the packages built in the same job.

apko installs exactly the packages listed in the lockfile and silently drops
any config package missing from it, so `merge` is also where drift between
apko.yaml and its lock is caught.

  lockfile.py strip FRESH OUT
      Drop local packages from a fresh `apko lock` output (committed lock).
  lockfile.py merge COMMITTED FRESH CONFIG OUT
      Write a build lock: FRESH's local packages + COMMITTED's Wolfi packages.
      Fails if CONFIG changed since COMMITTED was generated, or if the set of
      Wolfi packages FRESH resolves differs from COMMITTED's.
  lockfile.py diff OLD NEW
      Print a Markdown list of package changes between two locks.
  lockfile.py version LOCK PACKAGE
      Print PACKAGE's locked upstream version (Wolfi's -rN epoch dropped).
"""

import base64
import hashlib
import json
import sys


def is_local(pkg):
    return not pkg["url"].startswith(("https://", "http://"))


def load(path):
    with open(path) as f:
        return json.load(f)


def dump(lock, path):
    with open(path, "w") as f:
        json.dump(lock, f, indent=2)
        f.write("\n")


def config_checksum(path):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).digest()
    return "sha256-" + base64.b64encode(digest).decode()


def key(pkg):
    return (pkg["name"], pkg["architecture"])


def strip(fresh_path, out_path):
    lock = load(fresh_path)
    lock["contents"]["packages"] = [
        p for p in lock["contents"]["packages"] if not is_local(p)
    ]
    dump(lock, out_path)


def merge(committed_path, fresh_path, config_path, out_path):
    committed = load(committed_path)
    fresh = load(fresh_path)
    hint = f"regenerate it: task lock (see {committed_path})"

    if committed["config"]["checksum"] != config_checksum(config_path):
        sys.exit(f"error: {config_path} changed since its lock was generated; {hint}")

    pinned = {key(p): p for p in committed["contents"]["packages"]}
    wanted = {key(p) for p in fresh["contents"]["packages"] if not is_local(p)}
    missing = sorted(wanted - pinned.keys())
    extra = sorted(pinned.keys() - wanted)
    if missing or extra:
        for name, arch in missing:
            print(f"  not in lock: {name} ({arch})", file=sys.stderr)
        for name, arch in extra:
            print(f"  no longer needed: {name} ({arch})", file=sys.stderr)
        sys.exit(f"error: lock is out of step with the resolved package set; {hint}")

    # Keep fresh's install order; swap each Wolfi entry for its pinned one.
    fresh["contents"]["packages"] = [
        p if is_local(p) else pinned[key(p)] for p in fresh["contents"]["packages"]
    ]
    dump(fresh, out_path)

    for p in fresh["contents"]["packages"]:
        source = "local" if is_local(p) else "wolfi"
        print(f"  {source:5} {p['name']}={p['version']}")


def diff(old_path, new_path):
    def versions(path):
        try:
            packages = load(path)["contents"]["packages"]
        except FileNotFoundError:
            packages = []
        return {p["name"]: p["version"] for p in packages}

    old, new = versions(old_path), versions(new_path)
    for name in sorted(old.keys() | new.keys()):
        before, after = old.get(name), new.get(name)
        if before == after:
            continue
        if before is None:
            print(f"- `{name}`: added {after}")
        elif after is None:
            print(f"- `{name}`: removed (was {before})")
        else:
            print(f"- `{name}`: {before} → {after}")


def version(lock_path, name):
    for p in load(lock_path)["contents"]["packages"]:
        if p["name"] == name:
            print(p["version"].rsplit("-r", 1)[0])
            return
    sys.exit(f"error: {name} is not in {lock_path}")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "strip" and len(args) == 2:
        strip(*args)
    elif cmd == "merge" and len(args) == 4:
        merge(*args)
    elif cmd == "diff" and len(args) == 2:
        diff(*args)
    elif cmd == "version" and len(args) == 2:
        version(*args)
    else:
        sys.exit(__doc__)
