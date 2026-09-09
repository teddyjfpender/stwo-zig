#!/usr/bin/env python3
"""Fresh-process acceptance of the tiny detached two-child parent development proof.

Requires independently supplied verifier, key and expected-root SHA256 pins.
Optional production exits before fresh verification; only production takes the
shared build lock. Verification needs no native inputs or producer state.
Every hostile case uses a temporary copy; proof mutations reseal transport hashes.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from riscv_segment_v2_detached_gate import MODULUS, sha256, shifted
from zig_serial_build import build_lock


def digest(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("expected a 32-byte SHA256 hex digest")
    return value.lower()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", type=digest, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--key-sha256", type=digest, required=True)
    parser.add_argument("--expected-root", type=Path, required=True)
    parser.add_argument("--expected-root-sha256", type=digest, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--publication-mode", choices=("root", "intermediate"), default="root")
    parser.add_argument("--memory-profile", choices=("initial", "continuation"), default="initial")
    parser.add_argument("--child-family", choices=("segment", "parent"), default="segment")
    parser.add_argument("--producer", type=Path, help="produce a new candidate before fresh verification")
    parser.add_argument("--producer-sha256", type=digest)
    parser.add_argument("--parent-key", type=Path, help="independently admitted key, required for production")
    parser.add_argument("--left", nargs=3, metavar=("BUNDLE", "KEY_SHA256", "EXPECTED_WIRE"))
    parser.add_argument("--right", nargs=3, metavar=("BUNDLE", "KEY_SHA256", "EXPECTED_WIRE"))
    args = parser.parse_args()
    if args.memory_profile == "continuation" and args.publication_mode != "intermediate":
        parser.error("continuation memory profile requires intermediate publication")
    if args.child_family == "parent" and args.memory_profile != "initial":
        parser.error("parent children do not accept a native memory profile")
    verifier, bundle, expected, output = (
        path.resolve() for path in (args.verifier, args.bundle, args.expected_root, args.output))
    if output.exists() or output.is_relative_to(bundle):
        parser.error("report must be a new path outside the retained bundle")
    artifacts = [bundle / name for name in ("key.json", "claims.json", "proof.bin")]
    production_options = (args.producer, args.producer_sha256, args.parent_key, args.left, args.right)
    if any(production_options) and not all(production_options):
        parser.error("production requires producer/hash, admitted parent key and both admitted children")
    inputs = [verifier, expected]
    pins = [(verifier, args.verifier_sha256), (expected, args.expected_root_sha256)]
    if args.producer:
        if bundle.exists():
            parser.error("production requires a new bundle directory")
        inputs += [args.producer.resolve(), args.parent_key.resolve()]
        pins += [(args.producer.resolve(), args.producer_sha256), (args.parent_key.resolve(), args.key_sha256)]
        for child in (args.left, args.right):
            child[0], child[2] = str(Path(child[0]).resolve()), str(Path(child[2]).resolve())
            try:
                child[1] = digest(child[1])
            except argparse.ArgumentTypeError as error:
                parser.error(str(error))
            inputs += [Path(child[0]) / name for name in ("key.json", "claims.json", "proof.bin")]
            inputs.append(Path(child[2]))
            pins.append((Path(child[0]) / "key.json", child[1]))
        if any(path.is_relative_to(bundle) for path in inputs):
            parser.error("admitted inputs must exist outside the new bundle")
    else:
        inputs += artifacts
        pins.append((artifacts[0], args.key_sha256))
    unchanged = {path: sha256(path) for path in inputs}
    for path, pin in pins:
        if unchanged[path] != pin:
            parser.error(f"independent SHA256 pin mismatch: {path}")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"gate_sha256": sha256(Path(__file__)), "development_only": True,
              "verifier_sha256": args.verifier_sha256, "key_sha256": args.key_sha256,
              "expected_root_sha256": args.expected_root_sha256,
              "original_files": {str(path): pin for path, pin in unchanged.items()},
              "cases": [], "passed": False}

    def invoke(name: str, directory: Path = bundle, pin: str = args.key_sha256,
               root: Path = expected, *, accept: bool = False,
               error: str | tuple[str, ...] | None = None) -> None:
        # Each call exits before the next starts. No producer owners or in-process
        # verifier caches can cross this boundary. Timings are diagnostics only.
        argv = [str(verifier), str(directory), pin, str(root)]
        entry = {"case": name, "argv": argv, "expected_acceptance": accept,
                 "key_sha256": pin, "expected_root_sha256": sha256(root),
                 "artifact_sha256": {p: sha256(directory / p)
                                     for p in ("key.json", "claims.json", "proof.bin")}}
        report["cases"].append(entry)
        started = time.monotonic_ns()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            entry["timed_out"] = True
            raise
        finally:
            entry["process_ns"] = time.monotonic_ns() - started
        entry.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode < 0 or (result.returncode == 0) != accept:
            raise RuntimeError(f"{name}: verifier crashed or returned unexpected acceptance")
        if accept:
            receipt = json.loads(result.stdout)
            entry["receipt"] = receipt
            for field, value in {
                "endpoint": ("verified_segment_v2_detached_two_child_parent_development_q3" if args.publication_mode == "root"
                             else "verified_segment_v2_detached_intermediate_parent_development_q3"),
                "development_only": True, "verified": True, "native_inputs_used": False,
                "key_sha256": list(bytes.fromhex(pin)),
                "expected_root_sha256": list(bytes.fromhex(sha256(root))),
                "claims_sha256": list(bytes.fromhex(sha256(directory / "claims.json"))),
                "proof_sha256": list(bytes.fromhex(sha256(directory / "proof.bin"))),
                "proof_bytes": (directory / "proof.bin").stat().st_size,
            }.items():
                if receipt.get(field) != value:
                    raise RuntimeError(f"{name}: receipt mismatch: {field}")
        elif not re.search(r"(?m)^error: [A-Za-z][A-Za-z0-9_]*\s*$", result.stderr):
            raise RuntimeError(f"{name}: missing explicit verifier error (not a clean rejection)")
        if error and not any(re.search(rf"(?m)^error: {re.escape(value)}\s*$", result.stderr)
                             for value in ((error,) if isinstance(error, str) else error)):
            raise RuntimeError(f"{name}: did not reach required rejection boundary {error}")

    try:
        if args.producer:
            profile = "tiny-memory-root-v2" if args.publication_mode == "root" else "tiny-memory-span-v2"
            if args.memory_profile == "continuation":
                profile = "tiny-memory-continuation-span-v2"
            if args.child_family == "parent":
                profile = "tiny-parent-root-v2" if args.publication_mode == "root" else "tiny-parent-span-v2"
            argv = [str(args.producer.resolve()), "--profile", profile, str(bundle),
                    *args.left, *args.right, "--parent-key", str(args.parent_key.resolve()),
                    "--parent-key-sha256", args.key_sha256]
            log = output.with_name(output.name + ".producer.log")
            production = {"argv": argv, "log": str(log), "exited_before_verification": False}
            report["producer"] = production
            with build_lock(label="segment-v2-parent-complete-proof"), log.open("x") as stream:
                started = time.monotonic_ns()
                result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
                production.update(exit_code=result.returncode, process_ns=time.monotonic_ns() - started,
                                  exited_before_verification=True)
            production["log_sha256"] = sha256(log)
            if result.returncode:
                raise RuntimeError(f"parent producer failed; retained log: {log}")
            records = [json.loads(line) for line in log.read_text().splitlines() if line.startswith('{')]
            if len(records) != 1:
                raise RuntimeError("missing unique parent producer lifecycle record")
            lifecycle = records[0]
            for field, value in {"status": "unverified_candidate", "verified": False,
                                 "development_only": True, "child_owners_destroyed": True,
                                 "producer_destroyed": True, "reused_admitted_parent_key": True}.items():
                if lifecycle.get(field) != value:
                    raise RuntimeError(f"parent producer lifecycle mismatch: {field}")
            production["lifecycle"] = lifecycle
            if sha256(artifacts[0]) != args.key_sha256:
                raise RuntimeError("produced parent key differs from independent admission")
            unchanged.update({path: sha256(path) for path in artifacts})
            report["original_files"] = {str(path): pin for path, pin in unchanged.items()}
        # Trust checks above precede execution; genuine acceptance precedes every
        # mutation, including assertions about this development wire profile.
        invoke("genuine", accept=True)
        key_bytes, claims_bytes, proof = [path.read_bytes() for path in artifacts]
        key, claims = json.loads(key_bytes), json.loads(claims_bytes)
        if key["version"] not in (1, 2) or claims["version"] != key["version"] or len(claims["claims"]["values"]) != 36:
            raise RuntimeError("unsupported parent transport version/claim inventory")
        if key.get("publication_mode", "root") != args.publication_mode:
            raise RuntimeError("admitted key does not match requested publication mode")
        if proof[:7] != bytes([0, 1, 3, 0, 1, 0, 4]):
            raise RuntimeError("unsupported canonical q3 parent proof prefix")
        with tempfile.TemporaryDirectory(prefix="segment-v2-parent-replay-") as temporary:
            work = Path(temporary)

            def candidate(name: str, *, changed_proof: bytes = proof,
                          changed_claims: dict | None = None, changed_key: dict | None = None) -> Path:
                directory = work / name
                directory.mkdir()
                envelope = copy.deepcopy(claims if changed_claims is None else changed_claims)
                envelope["proof_bytes"] = len(changed_proof)
                envelope["proof_sha256"] = list(hashlib.sha256(changed_proof).digest())
                (directory / "key.json").write_bytes(
                    key_bytes if changed_key is None else json.dumps(changed_key).encode())
                (directory / "claims.json").write_text(json.dumps(envelope))
                (directory / "proof.bin").write_bytes(changed_proof)
                return directory

            for name, data in {
                "changed_proof_config": bytes([1]) + proof[1:],
                "noncanonical_varint": bytes([0x80, 0]) + proof[1:],
                "forged_commitment_length": proof[:6] + bytes([0xff] * 9 + [1]) + proof[7:],
                "truncated": proof[:-1], "trailing": proof + b"\x00",
                "altered_proof_tail": proof[:-1] + bytes([proof[-1] ^ 1]),
            }.items():
                invoke(name, candidate(name, changed_proof=data))
            for name in ("changed_claim", "balanced_claims", "balanced_provider_partials"):
                changed = copy.deepcopy(claims)
                values = changed["claims"]
                if name == "balanced_provider_partials":
                    shifted(values["poseidon_partials"][0], 1)
                    shifted(values["poseidon_partials"][1], -1)
                else:
                    shifted(values["values"][0], 1)
                    if name == "balanced_claims":
                        shifted(values["values"][1], -1)
                invoke(name, candidate(name, changed_claims=changed))
            for row in range(14, 20):
                changed = copy.deepcopy(claims)
                shifted(changed["claims"]["values"][row], 1)
                name = f"inactive_claim_{row}"
                invoke(name, candidate(name, changed_claims=changed), error="DetachedParentInactiveClaim")
            changed = copy.deepcopy(claims)
            changed["version"] += 1
            invoke("claims_version", candidate("claims_version", changed_claims=changed),
                   error="DetachedParentClaimsEnvelopeMismatch")
            for name in ("key_version", "key_config"):
                changed = copy.deepcopy(key)
                if name == "key_version":
                    changed["version"] += 1
                else:
                    changed["pcs_config"]["pow_bits"] += 1
                directory = candidate(name, changed_key=changed)
                # Diagnostic re-pin reaches profile admission; this never replaces
                # the independently supplied pin used by genuine verification.
                invoke(name, directory, sha256(directory / "key.json"), error="DetachedParentProfileMismatch")
            wrong_pin = ("1" if args.key_sha256[0] == "0" else "0") + args.key_sha256[1:]
            invoke("wrong_independent_key_pin", pin=wrong_pin, error="DetachedParentKeyHashMismatch")
            words = json.loads(expected.read_bytes())
            if len(words) != (436 if key["version"] == 2 else 412) or any(type(word) is not int or not 0 <= word < MODULUS for word in words):
                raise RuntimeError("unsupported expected-root word ABI")
            # span_statement_executed_span.canonical_layout.program_start == 11
            # in V1. The digest has no integer/tag/coverage restrictions. Requiring
            # claim closure rejection below proves canonical admission succeeded.
            words[11] = (words[11] + 1) % MODULUS
            changed_root = work / "changed-canonical-root.json"
            changed_root.write_text(json.dumps(words))
            invoke("changed_canonical_expected_root", root=changed_root,
                   error="DetachedParentClaimClosureMismatch")
            if key["version"] == 2:
                changed_key = copy.deepcopy(key)
                changed_key["publication_mode"] = "intermediate" if key["publication_mode"] == "root" else "root"
                changed_directory = candidate("changed_publication_mode", changed_key=changed_key)
                invoke("changed_publication_mode", changed_directory, sha256(changed_directory / "key.json"),
                       error=("DetachedParentClaimClosureMismatch", "RootSlotStartMismatch", "RootHeightNotMinimal")
                       if args.publication_mode == "intermediate" else "DetachedParentClaimClosureMismatch")
                for name, index in (("session", 412), ("entry_lineage", 420), ("exit_lineage", 428)):
                    words = json.loads(expected.read_bytes())
                    words[index] = (words[index] + 1) % MODULUS
                    changed_root = work / f"changed-{name}.json"
                    changed_root.write_text(json.dumps(words))
                    invoke(f"changed_published_{name}", root=changed_root,
                           error="DetachedParentClaimClosureMismatch")
        report["passed"] = True
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        changed_files = [str(path) for path, pin in unchanged.items()
                         if not path.is_file() or sha256(path) != pin]
        report["unchanged_files"] = not changed_files
        if changed_files:
            report.update(passed=False, changed_files=changed_files)
        with output.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        if changed_files:
            raise RuntimeError(f"retained inputs changed: {changed_files}")
    print(f"passed {len(report['cases'])} fresh-process parent cases; report={output}")


if __name__ == "__main__":
    main()
