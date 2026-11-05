#!/usr/bin/env python3
"""Independent-process boolean-AIR gate; no Ethereum or speed qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    def invoke(mode, degree, fold, codec, path, accepted):
        command = [args.binary, mode, str(degree), str(fold), codec, str(path)]
        run = subprocess.run(command, capture_output=True, text=True)
        if (run.returncode == 0) != accepted:
            raise RuntimeError(f"unexpected result: {command}: {run.returncode}: {run.stderr}")
        results.append({"command": command, "exit_code": run.returncode,
                        "expected_accept": accepted, "stderr": run.stderr})
    files = []
    # Every producer exits before any receiver starts. No shared object/cache.
    for degree in [4, 8]:
        for fold in [1, 4]:
            for codec in ["binary", "json"]:
                path = out / f"d{degree}-f{fold}.{codec}"
                invoke("produce", degree, fold, codec, path, True)
                files.append((degree, fold, codec, path))
    for degree, fold, codec, path in files:
        invoke("verify", degree, fold, codec, path, True)
    source = (out / "d8-f1.binary").read_bytes()
    # Six config u32s + root count follow the 8-byte magic. Main is root1.
    offset = 8 + 6 * 4 + 4 + 36
    root = bytearray(source)
    value = struct.unpack_from("<I", root, offset)[0]
    struct.pack_into("<I", root, offset, (value + 1) % 2147483647)
    noncanonical = bytearray(source)
    struct.pack_into("<I", noncanonical, offset, 2147483647)
    mutants = {"root": bytes(root), "noncanonical": bytes(noncanonical),
               "truncated": source[:-1], "trailing": source + b"\x00",
               "legacy_magic": b"STWOPRW8" + source[8:]}
    for name, data in mutants.items():
        path = out / f"reject-{name}.binary"
        path.write_bytes(data)
        invoke("verify", 8, 1, "binary", path, False)
    invoke("verify", 4, 1, "binary", out / "d8-f1.binary", False)
    receipt = {"status": "PASS", "scope": "synthetic boolean AIR; separate-process receivers; no Ethereum profile activation",
               "positive_proof_files": len(files), "rejections": len(mutants) + 1,
               "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
               "files": {path.name: {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                         for _, _, _, path in files}, "processes": results}
    (out / "fresh-process-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({k: receipt[k] for k in ["status", "scope", "positive_proof_files", "rejections"]}))


if __name__ == "__main__":
    main()
