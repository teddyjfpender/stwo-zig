#!/usr/bin/env python3
"""Verify a retained field wrapper and mutations in separate fresh processes.

The circuit hash must be admitted separately. This command never rebuilds a
circuit, opens native children, or changes the original proof directory.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

if __package__:
    from .zig_serial_build import build_lock
else:
    from zig_serial_build import build_lock


# These deliberate mutations must fail in admission, decoding or verification.
# Unknown errors fail the gate; resource and I/O failures prove no rejection.
REJECTIONS = {
    "wrong-key-pin": {"EthereumRootKeyHashMismatch"},
    "changed-claim": {"InvalidEthereumRootClaimClosure"},
    "changed-nonce": {"InvalidEthereumRootInteractionPow", "InvalidEthereumRootClaimClosure"},
    "changed-public-input": {"InvalidEthereumRootInteractionPow", "InvalidEthereumRootClaimClosure"},
    "changed-proof": {
        "ProofOfWork", "OodsNotMatching", "RootMismatch", "InvalidStructure",
        "FirstLayerEvaluationsInvalid", "FirstLayerCommitmentInvalid",
        "InnerLayerCommitmentInvalid", "InnerLayerEvaluationsInvalid",
        "LastLayerDegreeInvalid", "LastLayerEvaluationsInvalid",
        "EndOfStream", "NonCanonicalM31", "NonCanonicalVarint", "VarintOverflow",
        "TrailingProofBytes", "InvalidProofShape",
    },
}

PUBLIC_FIXTURE_CASES = ("changed-statement", "changed-boundary", "changed-position")
KEY_FIXTURE_CASES = ("changed-protocol", "changed-circuit-parameter")
# Match the root command's transport budgets. Real admitted keys include the
# fixed wire terms and can exceed 16 MiB even though public inputs are small.
FIXTURE_FILE_LIMITS = {"inputs_file": 128 * 1024, "key_file": 64 * 1024 * 1024}
for _case in (*PUBLIC_FIXTURE_CASES, "changed-circuit-parameter"):
    REJECTIONS[_case] = REJECTIONS["changed-public-input"]
REJECTIONS["changed-protocol"] = {"InvalidTemporalParentProtocolAuthority"}


def sha(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x") as destination:
        json.dump(value, destination, indent=2)
        destination.write("\n")


def rejection_fixtures(directory: Path, manifest_pin: str, identities: dict, original: dict,
                       *, initial: bool) -> tuple[dict, dict]:
    """Admit shared-Zig-generated mutations without duplicating the public ABI."""
    manifest_path = directory / "manifest.json"
    if manifest_path.stat().st_size > 1024 * 1024 or sha(manifest_path) != manifest_pin:
        raise ValueError("rejection fixture manifest differs from its pin")
    manifest = json.loads(manifest_path.read_bytes())
    if (manifest.get("version") != 1 or manifest.get("initial_profile") is not initial or
            manifest.get("original_key_sha256") != identities["key.json"] or
            manifest.get("original_inputs_sha256") != identities["inputs.json"] or
            manifest.get("proof_sha256") != identities["proof.bin"] or
            manifest.get("proof_bytes") != original["proof_bytes"]):
        raise ValueError("rejection fixtures belong to another proof request")
    cases = manifest.get("cases", [])
    names = [case["name"] for case in cases]
    if len(names) != 5 or set(names) != set(PUBLIC_FIXTURE_CASES + KEY_FIXTURE_CASES):
        raise ValueError("require exactly the five statement, boundary and profile fixtures")
    files = {manifest_path: manifest_pin}
    admitted = {}
    for case in cases:
        paths = {}
        for field, pin_field in (("inputs_file", "inputs_sha256"), ("key_file", "expected_key_sha256")):
            filename = case[field]
            if not isinstance(filename, str) or Path(filename).name != filename or filename in (".", ".."):
                raise ValueError("fixture paths must be flat filenames")
            path = directory / filename
            if path.is_symlink() or not path.is_file() or path.stat().st_size > FIXTURE_FILE_LIMITS[field] or sha(path) != case[pin_field]:
                raise ValueError("rejection fixture file differs from its pin")
            files[path] = case[pin_field]
            paths[field] = path
        inputs = json.loads(paths["inputs_file"].read_bytes())
        public_case = case["name"] in PUBLIC_FIXTURE_CASES
        if public_case:
            if (case.get("test_only_alternate_key") is not False or
                    case["expected_key_sha256"] != identities["key.json"] or
                    inputs.get("node") == original["node"] or
                    {k: v for k, v in inputs.items() if k != "node"} !=
                    {k: v for k, v in original.items() if k != "node"}):
                raise ValueError("public fixture must change only the public node")
        elif (case.get("test_only_alternate_key") is not True or
              case["expected_key_sha256"] == identities["key.json"] or inputs != original):
            raise ValueError("profile fixture must change only its explicitly test-only key")
        admitted[case["name"]] = {**paths, "expected_key_sha256": case["expected_key_sha256"]}
    return admitted, files


def run(verifier: Path, bundle: Path, expected_key: str, output: Path, timeout: float, *, initial: bool = False,
        fixtures: Path | None = None, fixture_manifest_pin: str | None = None) -> bool:
    files = ["key.json", "inputs.json", "proof.bin"]
    if initial:
        files.append("rejected-public-inputs.json")
    identities = {name: sha(bundle / name) for name in files}
    if identities["key.json"] != expected_key:
        raise ValueError("circuit key differs from its independent pin")
    original = json.loads((bundle / "inputs.json").read_bytes())
    if (bytes(original["proof_sha256"]).hex() != identities["proof.bin"] or
            original["proof_bytes"] != (bundle / "proof.bin").stat().st_size):
        raise ValueError("original proof transport identity mismatch")
    binary_sha = sha(verifier)
    endpoint = "verified_ethereum_initial_field_leaf_wrapper" if initial else "verified_ethereum_field_leaf_wrapper"
    cases = ["genuine", "wrong-key-pin", "changed-claim", "changed-nonce", "changed-proof"]
    if (fixtures is None) != (fixture_manifest_pin is None):
        raise ValueError("rejection fixtures require their independently pinned manifest")
    admitted_fixtures, fixture_files = rejection_fixtures(
        fixtures, fixture_manifest_pin, identities, original, initial=initial,
    ) if fixtures is not None else ({}, {})
    public_mutation = None
    if initial:
        # The complete Initial38 producer retains a valid alternate public node
        # using the shared Zig hashing code; never duplicate Poseidon in this CLI.
        public_mutation = json.loads((bundle / "rejected-public-inputs.json").read_bytes())
        if (public_mutation.get("node") == original["node"] or
                {k: v for k, v in public_mutation.items() if k != "node"} !=
                {k: v for k, v in original.items() if k != "node"}):
            raise ValueError("retained public mutation must change only the public node")
        cases.extend(["changed-public-input", "changed-initial-lane-claim", "changed-initial-packet-claim"])
    cases.extend(admitted_fixtures)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "plan.json", {
        "version": 1, "endpoint": endpoint.removeprefix("verified_"), "initial_profile": initial,
        "source": str(bundle), "source_sha256": identities,
        "verifier": str(verifier), "verifier_sha256": binary_sha,
        "expected_key_sha256": expected_key, "native_inputs_used": False,
        "rejection_fixture_files": {str(path): pin for path, pin in fixture_files.items()},
    })
    results = []
    for name in cases:
        directory = output / name
        directory.mkdir()
        for filename in identities:
            shutil.copyfile(bundle / filename, directory / filename)
        inputs = copy.deepcopy(original)
        pin = expected_key
        if name in admitted_fixtures:
            fixture = admitted_fixtures[name]
            shutil.copyfile(fixture["key_file"], directory / "key.json")
            shutil.copyfile(fixture["inputs_file"], directory / "inputs.json")
            pin = fixture["expected_key_sha256"]
        elif name == "wrong-key-pin":
            pin = ("1" if pin[0] == "0" else "0") + pin[1:]
        elif name == "changed-public-input":
            inputs = copy.deepcopy(public_mutation)
        elif name in ("changed-claim", "changed-initial-lane-claim", "changed-initial-packet-claim"):
            # Mutate one canonical M31 coefficient in the QM31 claim. The
            # native verifier owns parsing and all algebraic acceptance checks.
            index = {"changed-claim": 0, "changed-initial-lane-claim": 36, "changed-initial-packet-claim": 37}[name]
            cell = inputs["claims"]["values"][index]["c0"]["a"]
            if type(cell["v"]) is not int:
                raise ValueError("unsupported canonical field JSON encoding")
            cell["v"] = (cell["v"] + 1) % 2147483647
        elif name == "changed-nonce":
            inputs["interaction_pow_nonce"] ^= 1
        elif name == "changed-proof":
            proof = bytearray((directory / "proof.bin").read_bytes())
            proof[-1] ^= 1
            (directory / "proof.bin").write_bytes(proof)
            # Reach canonical proof decoding/verification, past transport SHA.
            inputs["proof_sha256"] = list(hashlib.sha256(proof).digest())
        if inputs != original:
            (directory / "inputs.json").write_text(json.dumps(inputs) + "\n")
        argv = [str(verifier), *(["--initial-v1"] if initial else []), str(directory), pin]
        started = time.monotonic()
        result = {"case": name, "command": argv, "passed": False,
                  "inputs_sha256": sha(directory / "inputs.json"),
                  "proof_sha256": sha(directory / "proof.bin")}
        try:
            with build_lock(label=f"ethereum root {name}"), (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
                result["queue_wait_s"] = time.monotonic() - started
                process_started = time.monotonic()
                process = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
                result["process_s"] = time.monotonic() - process_started
            result["returncode"] = process.returncode
            if name == "genuine" and process.returncode == 0:
                receipt = json.loads((directory / "stdout.log").read_bytes())
                result["verifier_receipt"] = receipt
                result["passed"] = (receipt.get("endpoint") == endpoint and
                                    receipt.get("verified") is True and receipt.get("native_inputs_used") is False and
                                    bytes(receipt.get("key_sha256", [])).hex() == expected_key and
                                    bytes(receipt.get("proof_sha256", [])).hex() == identities["proof.bin"] and
                                    receipt.get("statement_words") == original["node"]["statement_words"] and
                                    receipt.get("coordinate") == original["node"]["coordinate"] and
                                    receipt.get("proof_bytes") == original["proof_bytes"] and
                                    receipt.get("output_digest") == original["node"]["output_digest"])
            elif name != "genuine":
                error = (directory / "stderr.log").read_text(errors="replace")
                rejection = re.findall(r"^error: ([A-Za-z][A-Za-z0-9_]*)\s*$", error, re.MULTILINE)
                policy = "changed-claim" if name.startswith("changed-initial-") else name
                result["rejection_error"] = rejection[0] if len(rejection) == 1 else None
                result["passed"] = (process.returncode == 1 and "panic:" not in error and
                                    result["rejection_error"] in REJECTIONS[policy])
        except (subprocess.TimeoutExpired, OSError, ValueError, TypeError, KeyError) as error:
            result["error"] = str(error)
        result["elapsed_s"] = time.monotonic() - started
        write_json(directory / "receipt.json", result)
        results.append(result)
        print(json.dumps(result), flush=True)
        if not result["passed"]:
            break
    unchanged = sha(verifier) == binary_sha and all(sha(bundle / name) == value for name, value in identities.items())
    unchanged = unchanged and all(sha(path) == pin for path, pin in fixture_files.items())
    passed = unchanged and len(results) == len(cases) and all(result["passed"] for result in results)
    write_json(output / "receipt.json", {"passed": passed, "source_and_verifier_unchanged": unchanged, "cases": results})
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verifier", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--expected-key-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--initial-v1", action="store_true", help="use the explicitly admitted Initial38 verifier and test its two additional claims")
    parser.add_argument("--rejection-fixtures", type=Path, help="shared Zig exporter output for same-proof statement, boundary and profile mutations")
    parser.add_argument("--rejection-manifest-sha256", help="pin emitted by the trusted rejection fixture exporter")
    args = parser.parse_args()
    pin = args.expected_key_sha256.lower()
    if len(pin) != 64 or any(word not in "0123456789abcdef" for word in pin) or args.timeout <= 0:
        parser.error("require a 64-character hexadecimal key SHA256 and positive timeout")
    if (args.rejection_fixtures is None) != (args.rejection_manifest_sha256 is None):
        parser.error("rejection fixtures require --rejection-manifest-sha256")
    return 0 if run(args.verifier.resolve(strict=True), args.bundle.resolve(strict=True), pin, args.output.resolve(), args.timeout,
                    initial=args.initial_v1, fixtures=args.rejection_fixtures.resolve(strict=True) if args.rejection_fixtures else None,
                    fixture_manifest_pin=args.rejection_manifest_sha256) else 1


if __name__ == "__main__":
    raise SystemExit(main())
