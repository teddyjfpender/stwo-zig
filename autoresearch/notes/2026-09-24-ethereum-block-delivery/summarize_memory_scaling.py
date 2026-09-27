"""Validate saved qualification artifacts and summarize actual recursive trees."""
from pathlib import Path
import argparse
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
RUNS = [
    ("stream-assembly-release-auth1-canonical-2048", 16),
    ("stream-terminal-planning-auth1-canonical-1024", 32),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-64", action="store_true",
                        help="Require the completed 64-leaf proof and include it in the report")
    args = parser.parse_args()
    runs = RUNS + ([("stream-terminal-planning-auth1-canonical-512", 64)]
                   if args.include_64 else [])
    results = []
    reference = None
    for stem, expected_leaves in runs:
        data = json.loads((HERE / (stem + ".json")).read_text())
        invocation = json.loads((HERE / (stem + "-invocation.json")).read_text())
        require(invocation["exit_code"] == 0, f"{stem}: failed invocation")
        require(data["complete_execution_proof_verified"], f"{stem}: unverified root")
        require(data["canonical"] and data["queries"] == 70 and data["pow_bits"] == 26,
                f"{stem}: security parameters differ")
        proof = (HERE / (stem + ".proof")).read_bytes()
        require(hashlib.sha256(proof).hexdigest() == data["proof_sha256"],
                f"{stem}: proof artifact hash differs")
        identity = {key: data[key] for key in
                    ("elf_sha256", "input_sha256", "output_sha256", "cycles")}
        identity["complete_job"] = data["statement"]["job"]["complete"]
        if reference is None:
            reference = identity
        require(identity == reference, f"{stem}: complete execution identity differs")
        require(data["segments"] == expected_leaves,
                f"{stem}: unexpected execution leaf count")
        require(data["recursive_proof_jobs"] == 2 * data["segments"] - 1,
                f"{stem}: incomplete binary proof tree")
        log = (HERE / (stem + ".log")).read_text()
        peak = re.search(r"^\s*(\d+)\s+peak memory footprint\s*$", log, re.M)
        require(peak is not None, f"{stem}: missing physical footprint")
        results.append({
            "artifact": stem,
            "verified": True,
            "execution_leaves": data["segments"],
            "aggregation_levels": data["segments"].bit_length() - 1,
            "recursive_proof_jobs": data["recursive_proof_jobs"],
            "tracked_peak_bytes": data["peak_bytes"],
            "process_peak_bytes": int(peak.group(1)),
            "total_ns": data["total_ns"],
            "proof_sha256": data["proof_sha256"],
        })
    result = {
        "scope": "CPU canonical q70/26 complete authentication guest; not an Ethereum block",
        "same_complete_execution_identity": True,
        "observations_per_configuration": 1,
        "results": results,
        "tracked_peak_change_16_to_32_percent":
            100 * (results[1]["tracked_peak_bytes"] / results[0]["tracked_peak_bytes"] - 1),
    }
    if args.include_64:
        result["tracked_peak_change_16_to_64_percent"] = 100 * (
            results[2]["tracked_peak_bytes"] / results[0]["tracked_peak_bytes"] - 1)
    (HERE / "memory-scaling-qualified-summary.json").write_text(
        json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
