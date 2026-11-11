#!/usr/bin/env python3
"""Export pinned upstream Kona OP-Sepolia executor fixtures to portable preimages.

RocksDB is a host-only import. No RocksDB dependency enters the RV64 guest.
"""

import argparse
import hashlib
import json
import tarfile
import urllib.request
from pathlib import Path

PIN = "a271fd6b3feb76e49f3453e5a27be4b33a3c7211"
BASE = f"https://raw.githubusercontent.com/ethereum-optimism/optimism/{PIN}/rust/kona/crates/proof/executor/testdata"
MAX_TAR = 8 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_MEMBERS = 4096


def validate_members(members):
    if len(members) > MAX_MEMBERS or sum(m.size for m in members) > MAX_EXPANDED:
        raise ValueError("fixture expands beyond bound")
    root = None
    paths = set()
    for member in members:
        path = Path(member.name)
        if (
            not (member.isdir() or member.isfile())
            or path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or member.size < 0
        ):
            raise ValueError("invalid fixture path/type")
        if root is not None and root != path.parts[0]:
            raise ValueError("fixture has multiple roots")
        root = path.parts[0]
        if path in paths:
            raise ValueError("duplicate fixture path")
        paths.add(path)
    return members


def export(archive, output):
    from rocksdict import Options, Rdict

    output.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = validate_members(tar.getmembers())
        for member in members:
            path = Path(member.name)
            if len(path.parts) > 1 and not path.name.startswith("._"):
                # Every fixture has one root directory. Avoid nesting that root twice.
                member.name = str(Path(*path.parts[1:]))
                tar.extract(member, output, filter="data")
    options = Options(raw_mode=True)
    options.create_if_missing(False)
    db = Rdict(str(output / "kv"), options)
    rows = sorted((key.hex(), value.hex()) for key, value in db.items())
    db.close()
    if any(len(key) != 64 for key, _ in rows):
        raise ValueError("non-32-byte execution preimage key")
    (output / "preimages.json").write_text(json.dumps(rows) + "\n")
    fixture = json.loads((output / "fixture.json").read_text())
    return {
        "block": int(fixture["parent_header"]["number"], 16) + 1,
        "chain_id": fixture["rollup_config"]["l2_chain_id"],
        "preimages": len(rows),
        "preimage_bytes": sum(len(value) // 2 for _, value in rows),
        "expected_block_hash": fixture["expected_block_hash"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--upstream", type=Path, help="Pinned Optimism checkout, instead of download"
    )
    parser.add_argument(
        "--blocks",
        type=int,
        nargs="+",
        default=[26207960, 26207961, 26207962, 26207963],
    )
    args = parser.parse_args()
    pins = json.loads(Path(__file__).with_name("fixtures.json").read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for block in args.blocks:
        name = f"block-{block}.tar.gz"
        expected = pins["fixtures"][name]
        archive = args.output / name
        if args.upstream:
            data = (
                args.upstream / "rust/kona/crates/proof/executor/testdata" / name
            ).read_bytes()
        elif archive.exists():
            data = archive.read_bytes()
        else:
            with urllib.request.urlopen(BASE + "/" + name, timeout=60) as response:
                data = response.read(MAX_TAR + 1)
        if (
            len(data) > MAX_TAR
            or len(data) != expected["bytes"]
            or hashlib.sha256(data).hexdigest() != expected["sha256"]
        ):
            raise ValueError("upstream fixture identity mismatch: " + name)
        archive.write_bytes(data)
        result = export(archive, args.output / f"block-{block}")
        result.update(archive_sha256=expected["sha256"], archive_bytes=len(data))
        results.append(result)
    (args.output / "fixture-receipt.json").write_text(
        json.dumps({"upstream_commit": PIN, "fixtures": results}, indent=2) + "\n"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
