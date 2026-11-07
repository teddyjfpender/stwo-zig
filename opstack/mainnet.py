#!/usr/bin/env python3
"""Import pinned historical OP Mainnet witnesses and admit them by native replay."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from Crypto.Hash import keccak

PIN = "85f22e11a0e7e946ae7e26905c21feef23a2a7df"
BASE = f"https://raw.githubusercontent.com/ethereum-optimism/kona-repro-pat/{PIN}"
SOURCE = "crates/executor/src/lib.rs"
LIMIT = 2 * 1024 * 1024


def checked(data, pin):
    if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise ValueError("archive identity mismatch")
    return data


def fetch(name, pin, cache):
    path = cache / name.replace("/", "_")
    if path.exists():
        return checked(path.read_bytes(), pin)
    with urllib.request.urlopen(BASE + "/" + name, timeout=60) as response:
        data = checked(response.read(LIMIT + 1), pin)
    path.write_bytes(data)
    return data


def digest(data):
    return keccak.new(digest_bits=256, data=data).hexdigest()


def preimages(data):
    # Preserve duplicate keys until after validation, including leading-zero aliases.
    pairs = json.loads(data, object_pairs_hook=lambda rows: rows)
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= 4096:
        raise ValueError("invalid preimage map size")
    records = {}
    for key, value in pairs:
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{1,64}", key):
            raise ValueError("invalid preimage key")
        key = key.zfill(64)
        if key in records:
            raise ValueError("duplicate normalized preimage key")
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
            raise ValueError("invalid preimage value")
        if digest(bytes.fromhex(value)) != key:
            raise ValueError("preimage authentication failed")
        records[key] = value
    return sorted(records.items())


def replay(source, block):
    candidates = []
    for section in re.split(r"(?m)^    fn test_l2_block_executor_", source)[1:]:
        if f"execution of block #{block} on OP mainnet." in section:
            candidates.append(section)
    if len(candidates) != 1:
        raise ValueError("ambiguous or missing mainnet source section")
    section = candidates[0]

    def literal(pattern):
        values = re.findall(pattern, section)
        if len(values) != 1:
            raise ValueError("ambiguous header literal")
        return values[0]

    parent = literal(r'let raw_(?:parent_)?header = hex!\("([0-9a-f]+)"\);')
    expected = literal(r'let raw_expected_header = hex!\("([0-9a-f]+)"\);')
    txs = re.findall(r'let raw_tx = hex!\("([0-9a-f]+)"\);', section)
    if not txs:
        group = re.findall(r"let raw_txs = alloc::vec!\[(.*?)\];", section, re.DOTALL)
        if len(group) != 1:
            raise ValueError("ambiguous transaction literals")
        txs = re.findall(r'hex!\("([0-9a-f]+)"\)', group[0])
    if not txs or len(txs) > 4096:
        raise ValueError("invalid transaction count")
    return {
        "chain_id": 10,
        "block_number": block,
        "parent_rlp": parent,
        "expected_rlp": expected,
        "expected_block_hash": "0x" + digest(bytes.fromhex(expected)),
        "transactions": ["0x" + tx for tx in txs],
    }


def command(args):
    result = subprocess.run(
        [str(x) for x in args], check=False, capture_output=True, text=True, timeout=300
    )
    if result.returncode:
        raise RuntimeError(
            f"mainnet command failed ({result.returncode}): {args}: {result.stderr.strip()}"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--blocks", nargs="+", type=int)
    args = parser.parse_args()
    pins = json.loads(Path(__file__).with_name("mainnet-fixtures.json").read_text())
    blocks = args.blocks or [int(b) for b in pins["blocks"]]
    if len(set(blocks)) != len(blocks) or any(
        str(b) not in pins["blocks"] for b in blocks
    ):
        parser.error("select unique pinned mainnet blocks")
    if args.output.exists():
        parser.error("output must be fresh")
    args.cache.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = fetch(SOURCE, pins["source"], args.cache).decode()
    with tempfile.TemporaryDirectory(
        prefix=".mainnet-", dir=args.output.parent
    ) as temporary:
        staging = Path(temporary) / "corpus"
        staging.mkdir()
        receipts = []
        for block in blocks:
            pin = pins["blocks"][str(block)]
            raw = fetch(
                f"crates/executor/testdata/block_{block}_exec/output.json",
                pin,
                args.cache,
            )
            rows = preimages(raw)
            out = staging / f"block-{block}"
            out.mkdir()
            metadata = replay(source, block)
            (out / "replay.json").write_text(json.dumps(metadata) + "\n")
            (out / "preimages.json").write_text(json.dumps(rows) + "\n")
            command(
                [args.host, "import-mainnet", out / "replay.json", out / "fixture.json"]
            )
            packed = out / "input.opx"
            command([args.host, "pack", packed, out])
            result = json.loads(command([args.host, "run", packed, "eager"]).stdout)
            if result["block_hashes"] != [metadata["expected_block_hash"]]:
                raise ValueError("mainnet expected block mismatch")
            receipts.append(
                {
                    "block": block,
                    "expected_block_hash": metadata["expected_block_hash"],
                    "archive": pin,
                    "preimages": len(rows),
                    "native": result,
                    "input_sha256": hashlib.sha256(packed.read_bytes()).hexdigest(),
                }
            )
        (staging / "fixture-receipt.json").write_text(
            json.dumps(
                {
                    "schema": "stwo.opstack.mainnet-corpus.v1",
                    "chain_id": 10,
                    "network": "OP Mainnet",
                    "coverage": "historical Ecotone execution; no L1 derivation",
                    "upstream_commit": PIN,
                    "source": pins["source"],
                    "fixtures": receipts,
                },
                indent=2,
            )
            + "\n"
        )
        shutil.move(str(staging), args.output)
    print(json.dumps(receipts, indent=2))


if __name__ == "__main__":
    main()
