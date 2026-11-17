"""Select a worker's native FRI capture and export the Solidity replay input."""

import argparse
import hashlib
import json
from pathlib import Path

from export_fri_layers import RECORD as FRI_RECORD, export_record
from export_pcs_suffix import RECORD as PCS_RECORD


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("diagnostic", "receipt", "worker", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--block", required=True, type=int)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    if not receipt["accepted"] or not receipt["completed_ethereum_block"]:
        raise ValueError("native receiver did not accept the complete block")

    worker = args.worker.read_bytes()
    worker_hash = hashlib.sha256(worker).digest()
    bundle = (args.worker.parent / "bundle.json").read_bytes()
    manifest = json.loads(bundle)
    workers = manifest["cpus"] + manifest["truths"]
    if (receipt["cpu_proofs"], receipt["truth_proofs"]) != (len(manifest["cpus"]), len(manifest["truths"])):
        raise ValueError("native receiver and manifest worker counts disagree")
    if not any(bytes(w["proof"]["sha256"]) == worker_hash and w["proof"]["bytes"] == len(worker) for w in workers):
        raise ValueError("worker does not match the bundle manifest")
    capture = args.diagnostic.read_text()
    records = []
    for prefix, sample_count, samples, roots, coefficient, digest, log in PCS_RECORD.findall(capture):
        roots = roots.split()
        if roots and all(bytes.fromhex(root) in worker for root in roots):
            records.append((prefix, sample_count, samples, roots, coefficient, digest, log))
    if len(records) != 1:
        raise ValueError(f"expected one native PCS record with roots in the worker, found {len(records)}")
    prefix, sample_count, samples, roots, coefficient, digest, log = records[0]
    matches = [record for record in FRI_RECORD.findall(capture) if record[0] == digest]
    if len(matches) != 1:
        raise ValueError(f"expected one intact FRI record for the worker, found {len(matches)}")
    nonce = matches[0][2]
    pcs = {
        "worker": args.worker.name, "workerSha256": worker_hash.hex(),
        "prefix": "0x" + prefix, "domainLog": int(log), "sampleCount": int(sample_count),
        "samples": "0x" + samples, "friRoots": ["0x" + root for root in roots],
        "lastCoefficient": "0x" + coefficient, "prePowDigest": "0x" + digest,
    }
    if len(samples) != 64 * int(sample_count) or len(coefficient) != 64:
        raise ValueError("bad OM31 transcript shape")
    fixture = export_record(matches[0], pcs, {"nonce": nonce})
    fixture["chainId"] = 10
    fixture["blockNumber"] = args.block
    fixture["bundleSha256"] = hashlib.sha256(bundle).hexdigest()
    fixture["prePowDigest"] = pcs.pop("prePowDigest")
    fixture["input"] = {key: value for key, value in pcs.items() if key not in ("worker", "workerSha256", "friRoots")}
    fixture["input"]["roots"] = pcs["friRoots"]
    fixture["input"]["nonce"] = nonce
    args.output.write_text(json.dumps(fixture, indent=2) + "\n")


if __name__ == "__main__":
    main()
