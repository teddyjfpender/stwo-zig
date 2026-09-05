#!/usr/bin/env python3
"""Restore purged campaign inputs from the content-addressed store.

macOS removes files under /private/tmp that have not been accessed for three
days. Campaign materialization results pin every input by path, byte count and
SHA-256, and the campaign import keeps a blob for each under
`<cas>/objects/sha256/<xx>/<sha256>.blob`, so a purged input can be put back
exactly where the materialization expects it and verified before use.

    python3 scripts/restore_campaign_inputs.py \\
        /private/tmp/<campaign>/authority/materialization-v2.json \\
        /private/tmp/<import>/cas

Prints one line per pinned path. Exit status is non-zero if any path is still
missing or fails its hash after the restore.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys


def pinned_identities(document) -> list[dict]:
    found: list[dict] = []
    seen: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            if {"path", "sha256", "bytes"} <= node.keys() and node["path"] not in seen:
                seen.add(node["path"])
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)
    return found


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    materialization, cas = sys.argv[1], sys.argv[2]
    with open(materialization) as handle:
        document = json.load(handle)

    failures = 0
    restored = 0
    for identity in pinned_identities(document):
        path = identity["path"]
        if os.path.exists(path):
            print(f"ok        {path}")
            continue
        blob = os.path.join(cas, "objects", "sha256", identity["sha256"][:2], identity["sha256"] + ".blob")
        if not os.path.exists(blob):
            print(f"MISSING   {path} (no blob {blob})")
            failures += 1
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copyfile(blob, path)
        size_ok = os.path.getsize(path) == int(identity["bytes"])
        hash_ok = sha256_of(path) == identity["sha256"]
        if size_ok and hash_ok:
            restored += 1
            print(f"restored  {path}")
        else:
            failures += 1
            print(f"CORRUPT   {path} (size ok={size_ok}, sha ok={hash_ok})")
    print(f"restored {restored}, failures {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
