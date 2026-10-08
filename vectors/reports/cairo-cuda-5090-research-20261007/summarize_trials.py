#!/usr/bin/env python3
"""Rebuild the compact 5090 experiment table from retained proof receipts."""

import csv
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
EXPECTED = {
    "15627902-15627904.prover_input": "980841d3e5dda240bfc88a28aa5a757d3d8418c4562678832af3079b7446c4d1",
    "15627905-15627907.prover_input": "02c0356818f99c29d169cbe984c7ba99a2af4552534798c764c5e8f15e656d05",
    "15582797_15582797": "fcc457fee3bcaca85efd97d308daa1a16e849c633b4571144417543158eb1eeb",
    "15567390_15567399": "2fa24723c44231d7c065d7befc81853f35b87d4e643109910510d9bb12913fe1",
    "15574540_15574549": "0d74ce722cfdadc65b046057fcef2a5a2da52d9fccc74fd85b69154b8cc90a39",
    "15554590_15554599": "8afdd44913e883e74d4bc0fbb41b1005d2f35c2d1a3df3558950527a9262a947",
    "15557240_15557249": "edf5a2bf729324f0a251393f68ca35a8ebccdae8a4221894c7b6366cd5e7593c",
    "15608951_15608963": "76e224838a6b74695aab566f5a5de6391568cd9e8c82acda63039133ca23ffb5",
    "15574910_15574919": "2157ac5287878e82ab29d16539897b6abeba162c6db6ee1827fdc8944106a632",
    "15563360_15563369": "7ddd6f9ce107c224f5823f4ee7535533c96327e61778118cfe74c39400b56f81",
    "15590913_15590913": "23ef11f1f7bbf0b31d6ede197bd67d2548975b951283c4cedc0fb6148e443af9",
}
INVALID_SOURCE = {
    "rtx5090-phased-writer-interaction",
    "rtx5090-phased-small",
    "rtx5090-relation-window-profile",
}
INVALID_POLICY = {"rtx5090-boundary-forced-managed-merkle"}
PHASE = re.compile(r"cairo-cuda-memory-phase phase=(\w+) elapsed_ns=(\d+)")
PHASE_COLUMNS = (
    ("trace_generation_s", "proof_begin", "trace_generation_end"),
    ("preprocessed_commit_s", "trace_generation_end", "preprocessed_commit_end"),
    ("main_commit_s", "preprocessed_commit_end", "main_commit_end"),
    ("relation_s", "main_commit_end", "relation_end"),
    ("interaction_commit_s", "relation_end", "interaction_commit_end"),
    ("constraint_s", "trace_commit_end", "constraint_evaluation_end"),
    ("tail_s", "constraint_evaluation_end", "decommit_end"),
)
FIELDS = (
    "variant", "pie", "status", "binary_sha256", "source_head", "source_diff_sha256",
    "policy_env_json", "full_command_s", "ingress_s", "proof_s",
    "adapted_to_publication_s", "device_peak_gib", "host_rss_peak_gib",
    *(entry[0] for entry in PHASE_COLUMNS), "proof_sha256", "rust_verified",
    "input_sha256", "error",
)


def seconds(ns: int | None) -> str:
    return "" if ns is None else f"{ns / 1e9:.6f}"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text()) if path.is_file() else {}


def one(directory: Path) -> dict:
    summary = read_json(directory / "summary.json")
    policy_env = dict(summary.get("policy_env", {}))
    # The first writer-scratch trial predated adding its key to the recorder's
    # allowlist. Keep the original receipt and its operator-command supplement.
    supplement = read_json(directory / "policy-env-supplement.json")
    if any(key in policy_env and policy_env[key] != value
           for key, value in supplement.items()):
        raise ValueError(f"conflicting policy supplement: {directory}")
    policy_env.update(supplement)
    report = read_json(directory / "report.json")
    trial = (report.get("completed_trials") or [{}])[0]
    verdict = read_json(directory / "official-verdict.json")
    proof_file = directory / "proof.sha256"
    file_sha = proof_file.read_text().split()[0] if proof_file.is_file() else ""
    verdict_sha = verdict.get("proof_sha256") or ""
    if file_sha and verdict_sha and file_sha != verdict_sha:
        raise ValueError(f"proof digest disagrees with verifier receipt: {directory}")
    proof_sha = file_sha or verdict_sha
    command = summary.get("command") or []
    variant = directory.parent.name
    pie = (Path(command[command.index("--input") + 1]).stem
           if "--input" in command else directory.name)
    phases = {name: int(value) for name, value in PHASE.findall(
        (directory / "process.log").read_text(errors="replace")
    )} if (directory / "process.log").is_file() else {}
    exact = bool(proof_sha and proof_sha == EXPECTED.get(pie))
    verified = verdict.get("verified") is True
    status = ("invalid_source" if variant in INVALID_SOURCE else
              "invalid_policy" if variant in INVALID_POLICY else
              "verified" if summary.get("exit_code") == 0 and exact and verified else
              "failed" if summary.get("exit_code") != 0 else "unqualified")
    input_sha = command[command.index("--input-sha256") + 1] if "--input-sha256" in command else ""
    log = (directory / "process.log").read_text(errors="replace") if (directory / "process.log").is_file() else ""
    errors = [line for line in log.splitlines() if "failed" in line or line.startswith("error:")]
    row = {
        "variant": variant, "pie": pie, "status": status,
        "binary_sha256": summary.get("binary_sha256") or "",
        "source_head": summary.get("source", {}).get("git_head") or "",
        "source_diff_sha256": summary.get("source", {}).get("git_diff_sha256") or "",
        "policy_env_json": json.dumps(policy_env, sort_keys=True),
        "full_command_s": seconds(summary.get("elapsed_ns")),
        "ingress_s": seconds(trial.get("ingress_ns")),
        "proof_s": seconds(trial.get("proof_execute_and_decode_ns")),
        "adapted_to_publication_s": seconds(trial.get("adapted_input_until_publication_ns")),
        "device_peak_gib": f"{summary.get('whole_device_peak_bytes', 0) / 2**30:.6f}",
        "host_rss_peak_gib": f"{summary.get('process_rss_peak_bytes', 0) / 2**30:.6f}",
        "proof_sha256": proof_sha, "rust_verified": str(verified).lower(),
        "input_sha256": input_sha, "error": errors[-1] if errors else "",
    }
    for column, begin, end in PHASE_COLUMNS:
        row[column] = seconds(phases[end] - phases[begin]) if begin in phases and end in phases else ""
    return row


def main() -> None:
    rows = [one(path) for path in ROOT.glob("rtx5090-*/*") if (path / "summary.json").is_file()]
    rows.sort(key=lambda row: (row["pie"], row["variant"]))
    with (ROOT / "measurements.csv").open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    qualified = [row for row in rows if row["status"] == "verified" and
                 row["adapted_to_publication_s"] and row["device_peak_gib"]]
    frontier = []
    for row in qualified:
        time = float(row["adapted_to_publication_s"])
        memory = float(row["device_peak_gib"])
        dominated = any(
            other["pie"] == row["pie"] and
            float(other["adapted_to_publication_s"]) <= time and
            float(other["device_peak_gib"]) <= memory and
            (float(other["adapted_to_publication_s"]) < time or
             float(other["device_peak_gib"]) < memory)
            for other in qualified
        )
        if not dominated:
            frontier.append(row)
    with (ROOT / "pareto.csv").open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(frontier)
    print(f"wrote {len(rows)} trials and {len(frontier)} exploratory Pareto points")


if __name__ == "__main__":
    main()
