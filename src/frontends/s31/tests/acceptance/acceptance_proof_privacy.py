#!/usr/bin/env python3
"""Native blinding, source/key downgrade and unsupported-profile acceptance.

Different trace commitments test fresh entropy; they do not establish ZK.
All witnesses and outputs in this driver are public test data.
"""

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))

import proof_privacy
import s31
from oracle import evaluate_relation
from text_frontend import compile_text

TEXT = """blinded circuit privacy_probe(private x: [m31; 4], public claim: [m31; 4]) -> public [m31; 4] {
    let square = x .* x;
    assert_eq(square, claim);
    claim
}
"""
P = 2**31 - 1


def run(*args: object, accepted: bool = True, error: str | None = None) -> str:
    result = subprocess.run([str(x) for x in args], cwd=s31.ROOT, text=True,
                            capture_output=True, timeout=300)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accepted or (error is not None and error not in output):
        raise AssertionError(f"unexpected exit {result.returncode}: {args}\n{output}")
    return output


def commitments(proof: bytes) -> tuple[bytes, bytes]:
    """Read only the fixed-profile header/config and first two postcard roots.

    Independent of the native decoder: S31NAT1, 11 QM31 claimed sums, followed
    by PcsConfigV2 and a Vec of 32-byte Blake2s roots. Reject other schedules.
    """
    if proof[:8] != b"S31NAT1\0":
        raise AssertionError("wrong native proof profile")
    offset = 8 + 8 + 11 * 16

    def varint() -> int:
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            byte = proof[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise AssertionError("bad varint")

    config = tuple(varint() for _ in range(5))
    # The wire carries log2(last-layer degree bound): bound 1 is encoded as 0.
    if config != (26, 1, 70, 0, 1) or proof[offset] != 0:
        raise AssertionError(f"unexpected proof config: {config}")
    offset += 1  # lifting_log_size = None
    if varint() != 4 or len(proof) < offset + 128:
        raise AssertionError("wrong commitment count")
    return proof[offset:offset + 32], proof[offset + 32:offset + 64]


def build_raw(source: Path, prefix: Path, *, key: Path | None = None,
              lowering: str = "gate", fold_step: int = 1) -> tuple[Path, Path]:
    options = []
    if key is not None:
        options.append(f"-Ds31-key={key}")
        lock = json.loads(key.read_text()).get("stdlib_lock_sha256")
        if lock:
            options.append(f"-Ds31-stdlib-sha256={lock}")
    run("zig", "build", "--build-file", s31.BUILD_FILE, "install", "-Doptimize=ReleaseFast",
        "-Ds31-version=1", f"-Ds31-lowering={lowering}", f"-Ds31-fri-fold-step={fold_step}",
        f"-Ds31-source={source}", "-Ds31-name=privacy_probe", *options, "--prefix", prefix)
    return prefix / "bin/s31-privacy_probe-prover", prefix / "bin/s31-privacy_probe-native-verifier"


def main() -> None:
    work = s31.ROOT / "zig-out/s31/privacy-acceptance"
    work.mkdir(parents=True, exist_ok=True)
    source_path = work / "privacy_probe.s31"
    source_path.write_text(TEXT)
    source, _ = compile_text(TEXT)
    package = s31.build(source_path, work / "blinded-package", "gate")
    manifest = s31.verify_package(package)
    prover = package / "bin/s31-privacy_probe-prover"
    verifier = package / "bin/s31-privacy_probe-native-verifier"
    key_path = package / "verification-key.json"
    key = json.loads(key_path.read_text())
    if key["proof_privacy"] != proof_privacy.POLICY or proof_privacy.RECURSIVE_ARTIFACTS.intersection(manifest["artifacts"]):
        raise AssertionError("blinding policy or package capabilities changed")
    assignment = {"public_inputs": {"claim": [81, 100, 121, 144]},
                  "private_inputs": {"x": [9, 10, 11, 12]},
                  "public_outputs": {"claim": [81, 100, 121, 144]}}
    statement = work / "statement.json"
    s31.write_json(statement, {k: v for k, v in assignment.items() if k != "private_inputs"})
    assignment_path = work / "assignment.json"
    proofs, roots, rejected = [], [], []
    for label, values in (("first", [9, 10, 11, 12]), ("repeat", [9, 10, 11, 12]),
                          ("other-private-witness", [P - n for n in (9, 10, 11, 12)])):
        assignment["private_inputs"]["x"] = values
        if evaluate_relation(source, assignment) != assignment["public_outputs"]:
            raise AssertionError("independent value oracle disagrees")
        s31.write_json(assignment_path, assignment)
        proof_path = work / f"{label}.proof"
        run(prover, "prove", assignment_path, proof_path)
        run(verifier, proof_path, statement, key_path)
        raw = proof_path.read_bytes()
        roots.append(commitments(raw))
        proofs.append({"label": label, "proof_bytes": len(raw),
                       "proof_sha256": hashlib.sha256(raw).hexdigest(),
                       "trace_root": roots[-1][1].hex()})
        print(f"native verifier accepted {label}; trace root {roots[-1][1].hex()}", flush=True)
    if len({root[0] for root in roots}) != 1 or len({root[1] for root in roots}) != 3:
        raise AssertionError("fixed preprocessed root and fresh trace roots required")
    first = work / "first.proof"

    bad_statement = work / "bad-statement.json"
    mutated = json.loads(statement.read_text())
    mutated["public_inputs"]["claim"][0] += 1
    s31.write_json(bad_statement, mutated)
    run(verifier, first, bad_statement, key_path, accepted=False)
    rejected.append("changed public statement")
    corrupt = work / "corrupt.proof"
    bytes_ = bytearray(first.read_bytes())
    bytes_[len(bytes_) // 2] ^= 1
    corrupt.write_bytes(bytes_)
    run(verifier, corrupt, statement, key_path, accepted=False)
    rejected.append("corrupt proof")
    for binary, command, args in ((prover, "recurse-keygen", (key_path, work / "outer.json")),
                                  (verifier, "recurse-verify", (first, statement)),
                                  (verifier, "fold-verify", (first, statement))):
        run(binary, command, *args, accepted=False, error="UnsupportedBlindingCommand")
        rejected.append(command)

    # Exercise the native boundary without relying on Python package checks.
    transparent_source = work / "transparent.s31.json"
    transparent = {k: v for k, v in source.items() if k != "proof_mode"}
    s31.write_json(transparent_source, transparent)
    old_prover, _ = build_raw(transparent_source, work / "transparent-binaries")
    unblinded = work / "transparent.proof"
    run(old_prover, "prove", assignment_path, unblinded)
    run(verifier, unblinded, statement, key_path, accepted=False)
    rejected.append("transparent proof under blinded key")
    old_report = json.loads(run(old_prover, "inspect"))
    if old_report["canonical_ir_sha256"] == key["canonical_ir_sha256"]:
        raise AssertionError("proof mode did not change canonical identity")

    mutations = {"stripped-policy": lambda k: k.pop("proof_privacy"),
                 "reduced-budget": lambda k: k["proof_privacy"].update(rounds=79),
                 "transparent-geometry": lambda k: k.update({field: old_report[field]
                     for field in ("preprocessed_root", "circuit_hash", "padded", "trace_log_size")})}
    for label, mutate in mutations.items():
        forged = copy.deepcopy(key)
        mutate(forged)
        forged_path = work / f"{label}.key.json"
        s31.write_json(forged_path, forged)
        _, forged_verifier = build_raw(package / "source.s31.json", work / label, key=forged_path)
        run(forged_verifier, first, statement, forged_path, accepted=False, error="InvalidVerificationKey")
        rejected.append(label)
        print(f"native verifier rejected sealed key: {label}", flush=True)

    for label, lowering, step in (("sparse-wide", "sparse-wide-gate", 1), ("fold-step-four", "gate", 4)):
        raw_prover, raw_verifier = build_raw(package / "source.s31.json", work / label,
                                           lowering=lowering, fold_step=step)
        run(raw_prover, "check", accepted=False, error="UnsupportedBlindingProfile")
        run(raw_verifier, first, statement, key_path, accepted=False, error="UnsupportedBlindingProfile")
        rejected.append(label)
        print(f"native entry points rejected unsupported profile: {label}", flush=True)

    # Even rehashing forged metadata must not remove the source privacy request.
    for label, field, value in (("manifest-mode", "proof_mode", "transparent"),
                                ("manifest-budget", "proof_privacy", {**proof_privacy.POLICY, "rounds": 0})):
        path = package / "manifest.json"
        original = path.read_bytes()
        try:
            s31.write_json(path, {**manifest, field: value})
            try:
                s31.verify_package(package)
            except ValueError:
                rejected.append(label)
            else:
                raise AssertionError("forged privacy metadata accepted")
        finally:
            path.write_bytes(original)
    report = {"schema": "s31-proof-privacy-acceptance-v1", "source_sha256": s31.file_hash(source_path),
              "compiler_sha256": manifest["compiler_sha256"], "policy": key["proof_privacy"],
              "proofs": proofs, "rejected": rejected,
              "scope": "native regression evidence for blinding; no ZK or complete Rust parity claim"}
    s31.write_json(work / "report.json", report)
    print(json.dumps({"accepted": len(proofs), "rejected": len(rejected), "report": str(work / "report.json")}))


if __name__ == "__main__":
    main()
