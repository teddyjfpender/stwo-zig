"""Resume serial STWIEF04 production, then freshly verify the complete bundle.

Run with python -m scripts.ethereum_full_leaf_bundle_producer. The Zig worker
owns proof and statement semantics; this adapter reuses controller file custody.
"""
from __future__ import annotations

import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import time

from scripts import ethereum_block_proof_materialization as materialization
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store
from scripts.zig_serial_build import build_lock


def run(*, prover: Path, verifier: Path, materialization_path: Path,
        publication_root: Path, output: Path, workers: int,
        host_byte_budget: int, host_byte_limit: int,
        timeout_seconds: int = 3600,
        selected_leaf_admission_root: Path | None = None,
        pcs_retained_byte_budget: int | None = None,
        claim_admission: str = "field_authority_v4",
        backend: str = "cpu", aot_bundle: Path | None = None,
        aot_manifest_sha256: str | None = None) -> dict:
    """One producer process at a time; committed leaves survive interruption.

    Every invocation finishes by re-verifying every proof in a fresh process,
    including resumed leaves, against the independently retained campaign job.
    """
    protocol.require(0 < workers and 0 < host_byte_budget <= host_byte_limit
                     and timeout_seconds > 0, "invalid explicit execution policy")
    protocol.require(claim_admission in ("field_authority_v4", "fixed_program_narrow_v5"),
                     "unsupported explicit claim admission")
    protocol.require(backend in ("cpu", "metal"), "unsupported prover backend")
    aot_files = {}
    if backend == "metal":
        protocol.require(aot_bundle is not None and aot_manifest_sha256 is not None,
                         "Metal requires an independently pinned AOT bundle")
        protocol._sha(aot_manifest_sha256, "Metal AOT manifest")
        aot_bundle = aot_bundle.resolve()
        store.require_directory(aot_bundle, "Metal AOT bundle")
        for name in ("stwo_zig_core.manifest.json", "stwo_zig_core.metal", "stwo_zig_core.metallib"):
            aot_files[name] = store.file_identity(aot_bundle / name, name)
        protocol.require(aot_files["stwo_zig_core.manifest.json"]["sha256"] == aot_manifest_sha256,
                         "Metal AOT manifest differs from independent pin")
    else:
        protocol.require(aot_bundle is None and aot_manifest_sha256 is None,
                         "CPU production does not accept Metal AOT options")
    if pcs_retained_byte_budget is not None:
        protocol.require(0 < pcs_retained_byte_budget <= host_byte_limit,
                         "PCS retained budget exceeds host admission limit")
    prover, verifier = prover.resolve(), verifier.resolve()
    materialization_path = materialization_path.resolve()
    publication_root, output = publication_root.resolve(), output.resolve()
    if selected_leaf_admission_root is not None:
        selected_leaf_admission_root = selected_leaf_admission_root.resolve()
        protocol.require(selected_leaf_admission_root != publication_root,
                         "selected leaf admissions must be separate from raw publication")
    admitted = materialization.validate_recursive(materialization_path)
    count = admitted["manifest"]["segment_count"]
    protocol.require(2 <= count <= 210, "unsupported retained campaign size")
    store.require_directory(output, "full leaf bundle output", create=True)
    staging = output / ".staging"
    store.require_directory(staging, "full leaf bundle staging", create=True)
    attempts = output / "attempts"
    store.require_directory(attempts, "full leaf bundle attempts", create=True)
    plan = {
        "schema": "stwo.ethereum.native-full-leaf-bundle-plan.v1",
        "prover": {"path": str(prover), **store.file_identity(prover, "prover")},
        "verifier": {"path": str(verifier), **store.file_identity(verifier, "verifier")},
        "materialization": {"path": str(materialization_path),
                            **store.file_identity(materialization_path, "materialization")},
        "publication_root": str(publication_root), "segment_count": count,
        "campaign_geometry": "authenticated-v1", "claim_admission": claim_admission,
        "workers": workers, "leaves_in_flight": 1,
        "host_byte_budget": host_byte_budget, "host_byte_limit": host_byte_limit,
    }

    # Keep the legacy sealed-campaign plan byte-for-byte stable when omitted.
    # Each selected leaf has one create-only admission across all retry attempts.
    if selected_leaf_admission_root is not None:
        plan["selected_leaf_admission"] = {
            "scope": "selected_leaf", "version": 1,
            "root": str(selected_leaf_admission_root),
        }

    if pcs_retained_byte_budget is not None:
        plan["pcs_retained_byte_budget"] = pcs_retained_byte_budget
    if backend == "metal":
        plan["backend"] = backend
        plan["aot"] = {"path": str(aot_bundle), "manifest_sha256": aot_manifest_sha256,
                       "files": aot_files}

    def publish(path: Path, value: dict) -> None:
        store.publish_new_or_identical(path, protocol.canonical_bytes(value), staging_directory=staging)

    def check_binary(path: Path, name: str) -> None:
        identity = {key: plan[name][key] for key in ("bytes", "sha256")}
        store.validate_file_identity(path, identity, name)
        if name == "prover" and aot_bundle is not None:
            for filename, expected in aot_files.items():
                store.validate_file_identity(aot_bundle / filename, expected, filename)

    def pending_production(index: int) -> Path | None:
        # A successful producer is only a candidate. Resume must still freshly
        # verify it; interrupted/failed verification must never trigger re-proving.
        for attempt in sorted(attempts.glob(f"leaf-{index:06d}-*"), reverse=True):
            store.require_directory(attempt, "retained producer attempt")
            execution_path = attempt / "execution.json"
            if not execution_path.exists():
                continue
            execution = store.read_canonical_json(execution_path, "producer execution")
            if execution["exit_code"] != 0:
                continue
            request = store.read_canonical_json(attempt / "request.json", "producer request")
            protocol.require(request["plan_sha256"] == protocol.sha256_bytes(protocol.canonical_bytes(plan)),
                             "pending producer campaign differs")
            leaf = json.loads(store.read_regular(attempt / "leaf.json", "pending leaf metadata", maximum=128 * 1024))
            protocol.require(leaf["metadata"]["segment_index"] == index, "pending leaf order differs")
            proof_sha = bytes(leaf["proof_sha256"]).hex()
            protocol._sha(proof_sha, "pending full leaf proof")
            store.validate_file_identity(attempt / "proof.bin",
                                         {"bytes": leaf["proof_bytes"], "sha256": proof_sha}, "pending full leaf proof")
            return attempt
        return None

    # Controller processes share this lock; no producer can overlap a resume.
    with (output / "controller.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        publish(output / "plan.json", plan)
        started = time.monotonic_ns()
        retained_leaves = {}
        pending_attempts = {}
        # Check the complete retained inventory before starting any new work.
        # Missing/corrupt proof files must not waste another long campaign.
        for index in range(count):
            leaf_path = output / f"leaf-{index:06d}.json"
            if leaf_path.exists():
                leaf = json.loads(store.read_regular(leaf_path, "retained leaf metadata", maximum=128 * 1024))
                protocol.require(leaf["metadata"]["segment_index"] == index, "retained leaf order differs")
                proof_sha = bytes(leaf["proof_sha256"]).hex()
                protocol._sha(proof_sha, "retained full leaf proof")
                store.validate_file_identity(output / f"{proof_sha}.bin",
                                             {"bytes": leaf["proof_bytes"], "sha256": proof_sha}, "retained full leaf proof")
                retained_leaves[index] = leaf
            else:
                pending_attempts[index] = pending_production(index)
        leaves = []
        for index in range(count):
            leaf_path = output / f"leaf-{index:06d}.json"
            if index not in retained_leaves:
                attempt = pending_attempts[index]
                if attempt is None:
                    attempt_index = 0
                    while (attempts / f"leaf-{index:06d}-{attempt_index:04d}").exists():
                        attempt_index += 1
                    attempt = attempts / f"leaf-{index:06d}-{attempt_index:04d}"
                    store.require_directory(attempt, "leaf attempt", create=True)
                    argv = [str(prover), "ethereum-incremental-full-leaf-replay-prepared-cpu-v1",
                            "--retained-materialization-result", str(materialization_path),
                            "--publication-root", str(publication_root),
                            "--campaign-geometry", "authenticated-v1",
                            "--claim-admission", claim_admission,
                            "--segment-index", str(index), "--output", str(attempt / "proof.bin"),
                            "--global-metadata-output", str(attempt / "leaf.json"),
                            "--workers", str(workers), "--host-byte-budget", str(host_byte_budget),
                            "--host-byte-limit", str(host_byte_limit)]
                    if backend == "metal":
                        del argv[1]  # Dedicated Metal product accepts the shared options directly.
                        argv.extend(["--aot-bundle", str(aot_bundle),
                                     "--aot-manifest-sha256", aot_manifest_sha256])
                    if pcs_retained_byte_budget is not None:
                        argv.extend(["--pcs-retained-byte-budget", str(pcs_retained_byte_budget)])
                    if selected_leaf_admission_root is not None:
                        argv.extend(["--selected-leaf-admission-root",
                                     str(selected_leaf_admission_root / f"leaf-{index:06d}")])
                    check_binary(prover, "prover")
                    publish(attempt / "request.json", {"argv": argv, "plan_sha256": protocol.sha256_bytes(protocol.canonical_bytes(plan))})
                    with build_lock(label=f"ethereum leaf {index}"), (attempt / "stdout.log").open("xb") as stdout, (attempt / "stderr.log").open("xb") as stderr:
                        process_started = time.monotonic_ns()
                        result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout_seconds, check=False)
                        process_ns = time.monotonic_ns() - process_started
                    publish(attempt / "execution.json", {"exit_code": result.returncode, "process_ns": process_ns})
                    check_binary(prover, "prover")
                    protocol.require(result.returncode == 0, f"leaf {index} failed; retained {attempt}")
                else:
                    check_binary(prover, "prover")
                    print(f"Ethereum leaf {index}: recovering produced candidate from {attempt}", flush=True)
                leaf = json.loads(store.read_regular(attempt / "leaf.json", "native leaf metadata", maximum=128 * 1024))
                proof = store.read_regular(attempt / "proof.bin", "native full leaf", maximum=512 * 1024 * 1024)
                proof_sha = protocol.sha256_bytes(proof)
                protocol.require(len(proof) == leaf["proof_bytes"] and bytes(leaf["proof_sha256"]).hex() == proof_sha,
                                 "native leaf artifact differs from verified metadata")
                store.publish_new_or_identical(output / f"{proof_sha}.bin", proof, staging_directory=staging)
                del proof
                metadata_path = attempt / "leaf.json"
            else:
                leaf = retained_leaves[index]
                metadata_path = leaf_path
            protocol.require(leaf["metadata"]["segment_index"] == index, "retained leaf order differs")
            proof_sha = bytes(leaf["proof_sha256"]).hex()
            # Verify each new or resumed artifact before starting another producer.
            # The final bundle verifier still independently checks the whole span.
            verify_attempt = attempts / f"verify-leaf-{index:06d}-{time.time_ns()}"
            store.require_directory(verify_attempt, "fresh leaf verifier attempt", create=True)
            mode = "verify-leaf-fixed-program-v5" if claim_admission == "fixed_program_narrow_v5" else "verify-leaf"
            argv = [str(verifier), mode, str(output / f"{proof_sha}.bin"),
                    str(metadata_path), str(materialization_path),
                    plan["materialization"]["sha256"], "--workers", str(workers)]
            check_binary(verifier, "verifier")
            publish(verify_attempt / "request.json", {"argv": argv, "plan_sha256": protocol.sha256_bytes(protocol.canonical_bytes(plan))})
            with build_lock(label=f"ethereum verify leaf {index}"), (verify_attempt / "stdout.json").open("xb") as stdout, (verify_attempt / "stderr.log").open("xb") as stderr:
                process_started = time.monotonic_ns()
                verified = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout_seconds, check=False)
                process_ns = time.monotonic_ns() - process_started
            publish(verify_attempt / "execution.json", {"exit_code": verified.returncode, "process_ns": process_ns})
            check_binary(verifier, "verifier")
            protocol.require(verified.returncode == 0, f"leaf {index} fresh verification failed; retained {verify_attempt}")
            receipt = json.loads(store.read_regular(verify_attempt / "stdout.json", "leaf verifier receipt", maximum=128 * 1024))
            if claim_admission == "fixed_program_narrow_v5":
                protocol.require(receipt["endpoint"] == "verified_native_selected_leaf_fixed_program_v5",
                                 "leaf verifier used wrong profile endpoint")
                receipt = receipt["verification"]
            protocol.require(receipt["endpoint"] == "verified_native_selected_leaf"
                             and receipt["segment_index"] == index
                             and receipt["segment_count"] == count
                             and receipt["worker_count"] == workers
                             and receipt["proof_bytes"] == leaf["proof_bytes"]
                             and bytes(receipt["proof_sha256"]).hex() == proof_sha
                             and bytes(receipt["metadata_file_sha256"]).hex() == store.file_identity(metadata_path, "leaf metadata")["sha256"]
                             and bytes(receipt["materialization_sha256"]).hex() == plan["materialization"]["sha256"]
                             and receipt["retained_admission_destroyed_before_proof"] is True,
                             "leaf verifier receipt differs from intended campaign")
            publish(leaf_path, leaf)
            leaves.append(leaf)
            print(f"Ethereum full leaf {index + 1}/{count} independently verified", flush=True)
        bundle = {"version": 1, "claim_admission": claim_admission, "leaves": leaves}
        publish(output / "bundle.json", bundle)
        bundle_sha = protocol.sha256_bytes(protocol.canonical_bytes(bundle))
        check_binary(verifier, "verifier")
        # The materialization hash pins the original intended job separately
        # from mutable/resumable leaf records. Zig checks the exact JobContext.
        argv = [str(verifier), str(output), bundle_sha, str(materialization_path), plan["materialization"]["sha256"], "--workers", str(workers)]
        if claim_admission == "fixed_program_narrow_v5":
            argv.insert(1, "verify-bundle-fixed-program-v5")
        verify_attempt = attempts / f"verify-{time.time_ns()}"
        store.require_directory(verify_attempt, "fresh bundle verifier attempt", create=True)
        publish(verify_attempt / "request.json", {"argv": argv, "plan_sha256": protocol.sha256_bytes(protocol.canonical_bytes(plan))})
        with build_lock(label="ethereum verify bundle"), (verify_attempt / "stdout.json").open("xb") as stdout, (verify_attempt / "stderr.log").open("xb") as stderr:
            process_started = time.monotonic_ns()
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout_seconds, check=False)
            process_ns = time.monotonic_ns() - process_started
        publish(verify_attempt / "execution.json", {"exit_code": result.returncode, "process_ns": process_ns})
        check_binary(verifier, "verifier")
        protocol.require(result.returncode == 0, f"bundle verification failed; retained {verify_attempt}")
        receipt = json.loads(store.read_regular(verify_attempt / "stdout.json", "bundle verifier receipt", maximum=128 * 1024))
        protocol.require(receipt["endpoint"] == "verified_native_full_leaf_bundle"
                         and receipt["leaf_count"] == count
                         and receipt["worker_count"] == workers
                         and bytes(receipt["manifest_sha256"]).hex() == bundle_sha
                         and bytes(receipt["materialization_sha256"]).hex() == plan["materialization"]["sha256"],
                         "bundle verifier receipt differs from intended campaign")
        result = {"schema": "stwo.ethereum.native-full-leaf-bundle-result.v1",
                  "receipt": receipt, "invocation_ns": time.monotonic_ns() - started,
                  "producer_processes_destroyed": True, "leaves_in_flight": 1}
        publish(verify_attempt / "result.json", result)
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("prover", "verifier", "materialization", "publication-root", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    for option in ("workers", "host-byte-budget", "host-byte-limit"):
        parser.add_argument(f"--{option}", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    parser.add_argument("--pcs-retained-byte-budget", type=int, help="Retained PCS evaluation ceiling, separate from composition allocation budget")
    parser.add_argument("--claim-admission", choices=("field_authority_v4", "fixed_program_narrow_v5"),
                        default="field_authority_v4", help="Explicit campaign circuit profile, pinned across resume")
    parser.add_argument("--backend", choices=("cpu", "metal"), default="cpu")
    parser.add_argument("--aot-bundle", type=Path, help="Required authenticated bundle for the dedicated Metal producer")
    parser.add_argument("--aot-manifest-sha256", help="Independent AOT manifest pin; Metal only")
    parser.add_argument("--selected-leaf-admission-root", type=Path,
                        help="Create immutable per-index leaf admissions from retained raw pairs; does not seal the campaign")
    args = vars(parser.parse_args())
    args["materialization_path"] = args.pop("materialization")
    print(json.dumps(run(**args)))


if __name__ == "__main__":
    main()
