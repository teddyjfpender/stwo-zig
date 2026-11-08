#!/usr/bin/env python3
"""Fresh-process acceptance and hostile replay of one genuine tiny wrapper.

The key pin and expected statement are explicit caller inputs. Mutations update
transport checksums, so malformed proof tests reach the verifier's real ingress.
Optional production uses the existing tiny two-segment runner and finishes
before fresh verification starts. Producer outputs never supply trusted key pins
or expected statements. Development results are not production-security results.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

from zig_serial_build import build_lock

MODULUS = (1 << 31) - 1


def shifted(value: dict, delta: int) -> None:
    limb = value["c0"]["a"]
    limb["v"] = (limb["v"] + delta) % MODULUS


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(output: str, prefix: str) -> list[dict[str, str]]:
    return [dict(word.split("=", 1) for word in line.split()[1:] if "=" in word)
            for line in output.splitlines() if line.startswith(prefix + " ")]


AOT_PROFILES = {"core-v2": "core_v2", "recursive-framework-v1": "recursive_framework_v1"}


def require_producer_lifecycle(output: str, backend: str, aot_pin: str | None, recursive_backend: str = "cpu", segment_count: int = 2, aot_profile: str | None = None) -> dict:
    if segment_count not in (1, 2, 4, 8):
        raise ValueError("unsupported small-tree segment count")
    native = records(output, "SEGMENT_V2_NATIVE_MEMORY")
    children = records(output, "SEGMENT_V2_TWO_CHILD_CANDIDATE")
    final = records(output, "SEGMENT_V2_TWO_CHILD_PRODUCER")
    if len(native) != segment_count or len(children) != segment_count or len(final) != 1:
        raise RuntimeError("producer did not report every destroyed child owner")
    for index, (native_child, child) in enumerate(zip(native, children)):
        expected_native = {"path": "temporal", "segment": str(index), "backend": backend,
                           "producer_live_bytes_after_destroy": "0", "before_fresh_decode": "true"}
        expected_child = {"segment": str(index), "completed": "true" if index == segment_count - 1 else "false",
                          "native_backend": backend, "producer_live_bytes_after_destroy": "0",
                          "status": "unverified_candidate", "parent_proof_created": "false"}
        # Keep the original two-segment fixture checks. Larger trees authenticate
        # clocks against their independently admitted statements in the verifier.
        if segment_count == 2:
            expected_child.update(first_cycle=str((0, 64)[index]), retired_cycles=str((64, 34)[index]))
        if any(native_child.get(k) != v for k, v in expected_native.items()) or any(
                child.get(k) != v for k, v in expected_child.items()):
            raise RuntimeError(f"child {index}: missing destruction or exact execution coverage")
        if int(child.get("proof_bytes", "0")) <= 0:
            raise RuntimeError(f"child {index}: missing serialized candidate")
    expected_final = {"status": "unverified_candidates", "native_backend": backend,
                      "owners_destroyed": "true", "parent_proof_created": "false"}
    if any(final[0].get(k) != v for k, v in expected_final.items()):
        raise RuntimeError("producer did not finish the complete destruction lifecycle")
    if any(child.get("recursive_backend", "cpu") != recursive_backend for child in children) or final[0].get("recursive_backend", "cpu") != recursive_backend:
        raise RuntimeError("producer used a different recursive backend")
    recursive_device = records(output, "SEGMENT_V2_TWO_CHILD_RECURSIVE_METAL")
    if recursive_backend == "metal":
        if len(recursive_device) != segment_count or any(row.get("segment") != str(index) or
                int(row.get("dispatches", "0")) <= 0 or int(row.get("poseidon_commits", "0")) <= 0
                for index, row in enumerate(recursive_device)):
            raise RuntimeError("producer did not use Metal for every recursive wrapper")
        # New producers report composition coverage explicitly. Preserve unknown
        # coverage in older pinned receipts; never infer it from zero fallbacks.
        if aot_profile == "recursive-framework-v1":
            for row in recursive_device:
                if "framework_dispatches" in row and (int(row["framework_dispatches"]) <= 0 or
                        row.get("host_composition_components") != "0"):
                    raise RuntimeError("recursive provider profile did not complete device composition")
    elif recursive_device:
        raise RuntimeError("unexpected recursive Metal execution")
    if backend == "metal":
        aot = records(output, "SEGMENT_V2_NATIVE_METAL_AOT")
        device = records(output, "SEGMENT_V2_TWO_CHILD_NATIVE_METAL")
        if len(aot) != 1 or aot[0].get("manifest_sha256") != aot_pin or aot[0].get("profile") != AOT_PROFILES[aot_profile or "core-v2"]:
            raise RuntimeError("producer did not authenticate the selected Metal AOT profile")
        if len(device) != segment_count or any(row.get("segment") != str(index) or
                int(row.get("dispatches", "0")) <= 0 or int(row.get("poseidon_commits", "0")) <= 0
                for index, row in enumerate(device)):
            raise RuntimeError("producer did not use Metal for every native child")
    return {"native": native, "children": children, "final": final[0], "recursive_metal": recursive_device}


def run_producer(args: argparse.Namespace, report: dict) -> None:
    producer = args.producer.resolve()
    directory = args.bundle.resolve().parent
    argv = [str(producer), "--memory-addresses", "1", "--two-segment-output", str(directory),
            "--native-backend", args.native_backend]
    if args.recursive_backend != "cpu":
        argv += ["--recursive-backend", args.recursive_backend]
    if args.proof_profile != "development_q3_v1":
        argv += ["--proof-profile", args.proof_profile]
    if args.initial_memory_word:
        argv += ["--initial-memory-word", str(args.initial_memory_word)]
    if args.native_backend == "metal":
        argv += ["--aot-bundle", str(args.aot_bundle.resolve()),
                 "--aot-manifest-sha256", args.aot_manifest_sha256]
        if args.aot_profile is not None:
            argv += ["--aot-profile", args.aot_profile]
    log = args.output.with_name(args.output.name + ".producer.log")
    record = {"argv": argv, "binary_sha256": sha256(producer), "log": str(log.resolve()),
              "exited_before_verification": False}
    report["producer"] = record
    # Only native/outer production owns the heavy lane. Verification below is
    # deliberately unlocked, so it remains usable during a separate build.
    try:
        with build_lock(label="segment-v2-complete-proof"), log.open("xb") as output:
            if directory.exists():
                raise RuntimeError("producer output appeared while waiting; refusing to overwrite evidence")
            started = time.monotonic_ns()
            try:
                result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
                                        timeout=300, check=False)
                record["exit_code"] = result.returncode
                record["exited_before_verification"] = True
            except subprocess.TimeoutExpired:
                # subprocess.run kills and waits for the child before raising.
                record["timed_out"] = True
                record["exited_before_verification"] = True
                raise
            finally:
                record["process_ns"] = time.monotonic_ns() - started
    finally:
        if log.is_file():
            record["log_sha256"] = sha256(log)
    if result.returncode != 0:
        raise RuntimeError(f"producer exited {result.returncode}; retained log: {log}")
    record["lifecycle"] = require_producer_lifecycle(log.read_text(), args.native_backend,
                                                   args.aot_manifest_sha256, args.recursive_backend, aot_profile=args.aot_profile)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-profile", choices=("development_q3_v1", "recursive_q193_v1"), default="development_q3_v1")
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--key-sha256", required=True)
    parser.add_argument("--expected-wire", type=Path, required=True)
    parser.add_argument("--other-expected-wire", type=Path)
    parser.add_argument("--require-root", action="store_true", help="require this proof to cover a complete one-segment job")
    parser.add_argument("--adjacent-bundle", type=Path)
    parser.add_argument("--adjacent-key-sha256")
    parser.add_argument("--adjacent-expected-wire", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--producer", type=Path, help="already-built shared two-segment producer")
    parser.add_argument("--native-backend", choices=("cpu", "metal"), default="cpu")
    parser.add_argument("--recursive-backend", choices=("cpu", "metal"), default="cpu")
    parser.add_argument("--initial-memory-word", type=lambda value: int(value, 0), default=0,
                        help="unsigned initial word for the one-address memory fixture")
    parser.add_argument("--aot-bundle", type=Path)
    parser.add_argument("--aot-manifest-sha256")
    parser.add_argument("--aot-profile", choices=tuple(AOT_PROFILES))
    args = parser.parse_args()
    if args.aot_profile is not None and (not args.producer or args.native_backend != "metal"):
        parser.error("AOT profile selection requires a Metal producer")
    if args.recursive_backend == "metal" and (not args.producer or args.native_backend != "metal"):
        parser.error("recursive Metal requires a complete Metal producer run")
    if not 0 <= args.initial_memory_word <= 0xffffffff:
        parser.error("initial memory word must fit in u32")
    adjacent_options = (args.adjacent_bundle, args.adjacent_key_sha256, args.adjacent_expected_wire)
    if args.require_root and (args.producer or any(adjacent_options)):
        parser.error("single-root replay uses an existing one-segment bundle without pair options")
    if any(adjacent_options) and not all(adjacent_options):
        parser.error("adjacent bundle, independent key pin and expected wire must be supplied together")
    verifier = args.verifier.resolve()
    bundle = args.bundle.resolve()
    expected = args.expected_wire.resolve()
    for name in ("key_sha256", "adjacent_key_sha256", "aot_manifest_sha256"):
        pin = getattr(args, name)
        if pin is not None:
            try:
                if len(pin) != 64 or len(bytes.fromhex(pin)) != 32:
                    raise ValueError()
            except ValueError:
                parser.error(f"{name.replace('_', '-')} must be a 32-byte hex digest")
            setattr(args, name, pin.lower())
    if args.producer:
        directory = bundle.parent
        if not all(adjacent_options) or bundle.name != "child-0" or args.adjacent_bundle.resolve() != directory / "child-1":
            parser.error("producer requires NEW_DIRECTORY/child-0 and adjacent NEW_DIRECTORY/child-1")
        if directory.exists():
            parser.error("producer output directory already exists; retain prior evidence")
        for wire in (expected, args.adjacent_expected_wire.resolve()):
            if not wire.is_file() or wire.is_relative_to(directory):
                parser.error("both expected wires must exist independently outside the producer directory")
        if args.output.resolve().is_relative_to(directory):
            parser.error("report must be outside the new producer directory")
        if args.native_backend == "metal" and not (args.aot_bundle and args.aot_manifest_sha256):
            parser.error("Metal production requires an explicit AOT bundle and manifest pin")
        if args.native_backend == "cpu" and (args.aot_bundle or args.aot_manifest_sha256):
            parser.error("CPU production does not accept AOT options")
        if args.output.with_name(args.output.name + ".producer.log").exists():
            parser.error("producer log already exists; retain prior evidence")
    elif args.native_backend != "cpu" or args.aot_bundle or args.aot_manifest_sha256 or args.initial_memory_word:
        parser.error("native backend, memory seed and AOT options require --producer")
    if args.output.exists():
        parser.error("output already exists; retain the prior result")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    results = []

    def invoke(name: str, arguments: list[str], accept: bool) -> None:
        started = time.monotonic_ns()
        result = subprocess.run(
            [str(verifier), *arguments],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=120, check=False,
        )
        entry = {"case": name, "expected_acceptance": accept,
                 "exit_code": result.returncode,
                 "process_ns": time.monotonic_ns() - started,
                 "output": result.stdout}
        if accept and result.returncode == 0:
            receipt = json.loads(result.stdout)
            entry["receipt"] = receipt
            if receipt.get("verified") is not True or receipt.get("native_inputs_used") is not False:
                raise RuntimeError(f"{name}: missing detached verification receipt")
            if args.require_root and (receipt.get("endpoint") != "verified_segment_v2_single_root"
                    or not isinstance(receipt.get("root"), dict)
                    or receipt.get("child", {}).get("verified") is not True):
                raise RuntimeError(f"{name}: missing complete single-segment root receipt")
        results.append(entry)
        if (result.returncode == 0) != accept:
            raise RuntimeError(f"{name}: unexpected verifier result: {result.stdout}")
        if not accept and result.returncode < 0:
            raise RuntimeError(f"{name}: verifier crashed instead of rejecting input")

    def run(name: str, directory: Path, pin: str, wire: Path, accept: bool) -> None:
        invoke(name, (["--root"] if args.require_root else []) + [str(directory), pin, str(wire)], accept)

    report = {"gate_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "verifier_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
              "key_sha256": args.key_sha256,
              "expected_wire_sha256": sha256(expected),
              "development_only": True, "proof_profile": args.proof_profile, "single_segment_root_required": args.require_root, "cases": results, "passed": False}
    trusted_paths = [verifier, expected]
    if args.adjacent_expected_wire:
        trusted_paths.append(args.adjacent_expected_wire.resolve())
    if args.other_expected_wire:
        trusted_paths.append(args.other_expected_wire.resolve())
    if args.producer:
        trusted_paths.append(args.producer.resolve())
    unchanged = {path: sha256(path) for path in trusted_paths}
    try:
        if args.producer:
            run_producer(args, report)
            for path, expected_hash in unchanged.items():
                if sha256(path) != expected_hash:
                    raise RuntimeError(f"trusted input changed during production: {path}")
        # All producer processes have exited before these artifacts are opened.
        # Expected statements and independent pins still come from the caller.
        key = (bundle / "key.json").read_bytes()
        proof = (bundle / "proof.bin").read_bytes()
        claims_bytes = (bundle / "claims.json").read_bytes()
        claims = json.loads(claims_bytes)
        if hashlib.sha256(key).hexdigest() != args.key_sha256:
            raise RuntimeError("the supplied independent key pin does not match key.json")
        if json.loads(key).get("profile") != args.proof_profile:
            raise RuntimeError("admitted key does not match the selected proof profile")
        report["proof_sha256"] = hashlib.sha256(proof).hexdigest()
        for artifact_bundle in (bundle, args.adjacent_bundle):
            if artifact_bundle:
                for filename in ("key.json", "claims.json", "proof.bin"):
                    path = artifact_bundle.resolve() / filename
                    unchanged[path] = sha256(path)
        # This gate runs only the small detached verifier (about 18 MiB in the
        # retained replay), so it need not queue behind native proving/builds.
        # Timings here are diagnostics; controlled benchmarks own scheduling.
        with tempfile.TemporaryDirectory(prefix="segment-v2-replay-") as temporary:
            work = Path(temporary)
            run("genuine", bundle, args.key_sha256, expected, True)
            # Exact admitted encodings, not offsets inferred from untrusted
            # proof bytes. Query193 uses a two-byte canonical varint.
            prefix = {"development_q3_v1": bytes([0, 1, 3, 0, 1, 0, 4]),
                      "recursive_q193_v1": bytes([16, 1, 193, 1, 0, 4, 0, 4])}[args.proof_profile]
            if not proof.startswith(prefix):
                raise RuntimeError("unsupported genuine proof prefix for the selected profile")
            count_at = len(prefix) - 1
            mutations = {
                "changed_pcs_config": bytes([proof[0] ^ 1]) + proof[1:],
                "noncanonical_varint": bytes([proof[0] | 0x80, 0]) + proof[1:],
                "forged_commitment_length": proof[:count_at] + bytes([0xff] * 9 + [1]) + proof[count_at + 1:],
                "truncated": proof[:-1],
                "trailing": proof + b"\x00",
                "altered_proof_tail": proof[:-1] + bytes([proof[-1] ^ 1]),
            }
            for name, changed_proof in mutations.items():
                directory = work / name
                directory.mkdir()
                changed_claims = copy.deepcopy(claims)
                changed_claims["proof_bytes"] = len(changed_proof)
                changed_claims["proof_sha256"] = list(hashlib.sha256(changed_proof).digest())
                (directory / "key.json").write_bytes(key)
                (directory / "claims.json").write_text(json.dumps(changed_claims))
                (directory / "proof.bin").write_bytes(changed_proof)
                run(name, directory, args.key_sha256, expected, False)
            claim_cases = ["changed_claim", "balanced_claims", "balanced_poseidon_partials"]
            if args.proof_profile == "recursive_q193_v1":
                claim_cases += ["missing_interaction_pow", "changed_interaction_pow"]
            else:
                claim_cases += ["unexpected_interaction_pow"]
            for name in claim_cases:
                directory = work / name
                directory.mkdir()
                changed_claims = copy.deepcopy(claims)
                values = changed_claims["claims"]
                if name == "missing_interaction_pow":
                    del values["interaction_pow"]
                elif name == "changed_interaction_pow":
                    values["interaction_pow"] ^= 1
                elif name == "unexpected_interaction_pow":
                    values["interaction_pow"] = 0
                elif name == "balanced_poseidon_partials":
                    shifted(values["poseidon_partials"][0], 1)
                    shifted(values["poseidon_partials"][1], -1)
                else:
                    shifted(values["values"][0], 1)
                    if name == "balanced_claims":
                        shifted(values["values"][1], -1)
                (directory / "key.json").write_bytes(key)
                (directory / "claims.json").write_text(json.dumps(changed_claims))
                (directory / "proof.bin").write_bytes(proof)
                run(name, directory, args.key_sha256, expected, False)
            wrong_pin = ("0" if args.key_sha256[0] != "0" else "1") + args.key_sha256[1:]
            run("wrong_independent_key_pin", bundle, wrong_pin, expected, False)
            if args.other_expected_wire:
                other = args.other_expected_wire.resolve()
                if other.read_bytes() == expected.read_bytes():
                    raise RuntimeError("other expected statement must differ")
                report["other_expected_wire_sha256"] = hashlib.sha256(other.read_bytes()).hexdigest()
                run("other_canonical_expected_statement", bundle, args.key_sha256, other, False)
            if args.adjacent_bundle:
                adjacent = args.adjacent_bundle.resolve()
                adjacent_wire = args.adjacent_expected_wire.resolve()
                if hashlib.sha256((adjacent / "key.json").read_bytes()).hexdigest() != args.adjacent_key_sha256:
                    raise RuntimeError("adjacent key does not match its independent pin")
                left = [str(bundle), args.key_sha256, str(expected)]
                right = [str(adjacent), args.adjacent_key_sha256, str(adjacent_wire)]
                report["adjacent"] = {
                    "key_sha256": args.adjacent_key_sha256,
                    "proof_sha256": hashlib.sha256((adjacent / "proof.bin").read_bytes()).hexdigest(),
                    "expected_wire_sha256": hashlib.sha256(adjacent_wire.read_bytes()).hexdigest(),
                }
                invoke("complete_adjacent_pair", ["--pair", *left, *right], True)
                invoke("swapped_children", ["--pair", *right, *left], False)
                invoke("duplicated_first_child", ["--pair", *left, *left], False)
                invoke("duplicated_final_child", ["--pair", *right, *right], False)
                invoke("missing_final_child", ["--pair", *left], False)
            for path, expected_hash in unchanged.items():
                if sha256(path) != expected_hash:
                    raise RuntimeError(f"input or artifact changed during lifecycle: {path}")
            report["unchanged_files"] = {str(path): digest for path, digest in unchanged.items()}
            report["passed"] = True
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        with args.output.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(f"passed {len(results)} fresh-process cases; report={args.output}")


if __name__ == "__main__":
    main()
