"""Export a native DEEP/FRI suffix after independent complete proof reception."""

import argparse
import hashlib
import json
import re
from pathlib import Path


RECORD = re.compile(
    r"^PCS_PREFIX ([a-f0-9]{64}) (\d+)\n"
    r"PCS_SAMPLES ([a-f0-9]*)\n"
    r"PCS_ROOTS ([a-f0-9 ]+)\n"
    r"PCS_LAST ([a-f0-9]*)\n"
    r"PCS_SUFFIX ([a-f0-9]{64}) (\d+)$",
    re.MULTILINE,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diagnostics", type=Path)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("queries", type=Path)
    parser.add_argument("worker")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    if not receipt["accepted"] or not receipt["completed_ethereum_block"]:
        raise ValueError("capture requires accepted complete native reception")
    query = json.loads(args.queries.read_text())[args.worker]
    candidates = []
    for match in RECORD.finditer(args.diagnostics.read_text()):
        prefix, count, samples, roots, last, pre_pow, domain = match.groups()
        if "0x" + pre_pow != query["prePowDigest"] or int(domain) != query["domainLog"]:
            continue
        roots = roots.split()
        if len(samples) != 64 * int(count) or len(last) != 64:
            raise ValueError("malformed OM31 samples or final coefficient")
        digest = hashlib.blake2s(bytes.fromhex(prefix + samples)).digest()
        for root in roots:
            if len(root) != 64:
                raise ValueError("invalid FRI root")
            digest = hashlib.blake2s(digest + bytes.fromhex(root)).digest()
        if hashlib.blake2s(digest + bytes.fromhex(last)).hexdigest() != pre_pow:
            raise ValueError("independent pre-PoW reconstruction disagrees")
        candidates.append({
            "worker": args.worker,
            "workerSha256": query["workerSha256"],
            "prefix": "0x" + prefix,
            "domainLog": int(domain),
            "sampleCount": int(count),
            "samples": "0x" + samples,
            "friRoots": ["0x" + root for root in roots],
            "lastCoefficient": "0x" + last,
            "prePowDigest": "0x" + pre_pow,
        })
    if len(candidates) != 1:
        raise ValueError(f"expected one intact capture, found {len(candidates)}")
    args.output.write_text(json.dumps(candidates[0], indent=2) + "\n")


if __name__ == "__main__":
    main()
