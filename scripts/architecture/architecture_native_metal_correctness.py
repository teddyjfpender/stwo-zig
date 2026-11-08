#!/usr/bin/env python3
"""Run one bounded CPU/Metal proof parity case against the pinned Rust oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.architecture_host_gate_lib import capture  # noqa: E402
from scripts.architecture_host_gate_lib.aggregate_parity import artifact  # noqa: E402


MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class CorrectnessError(ValueError):
    pass


def _binary(path: Path, label: str) -> Path:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_mode & 0o111 == 0
    ):
        raise CorrectnessError(f"{label} is not an executable regular file")
    return path.resolve(strict=True)


def _run(argv: list[str], cwd: Path, *, expected_success: bool) -> bytes:
    code, stdout, stderr, _ = capture.run(argv, cwd, 300)
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        raise CorrectnessError("correctness command output exceeds its bound")
    succeeded = code == 0
    if succeeded != expected_success:
        tail = stderr[-2000:].decode("utf-8", errors="replace")
        expectation = "accept" if expected_success else "reject"
        raise CorrectnessError(f"correctness command did not {expectation}: {tail}")
    return stdout


def _load_json(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CorrectnessError(f"duplicate correctness report field: {key}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise CorrectnessError(f"correctness report is not an object: {path}")
    return value


def _prove_cpu(
    binary: Path, output: Path, report: Path, cwd: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    _run([
        str(binary), "prove", "--example", "wide_fibonacci",
        "--log-n-rows", "8", "--sequence-len", "8", "--protocol", "smoke",
        "--output", str(output), "--report-out", str(report),
    ], cwd, expected_success=True)
    return _verified_proof(binary, output, report, cwd)


def _prove_metal(
    binary: Path, verifier: Path, output: Path, report: Path, cwd: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    encoded = _run([
        str(binary), "prove", "--example", "wide_fibonacci",
        "--log-n-rows", "8", "--sequence-len", "8", "--protocol", "smoke",
        "--proof-artifact-out", str(output),
    ], cwd, expected_success=True)
    report.write_bytes(encoded)
    return _verified_proof(verifier, output, report, cwd)


def _verified_proof(
    verifier: Path, output: Path, report: Path, cwd: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    document, _, proof_sha256 = artifact(output)
    if (
        document.get("generator") != "zig"
        or document.get("example") != "wide_fibonacci"
        or document.get("prove_mode") != "prove"
    ):
        raise CorrectnessError("Native proof statement identity drifted")
    _run(
        [str(verifier), "verify", "--artifact", str(output), "--protocol", "smoke"],
        cwd, expected_success=True,
    )
    return document, _load_json(report), proof_sha256


def _oracle(binary: Path, proof: Path, cwd: Path, *, accepted: bool) -> None:
    _run(
        [str(binary), "--mode", "verify", "--artifact", str(proof)],
        cwd, expected_success=accepted,
    )


def _mutate(document: dict[str, Any], path: Path) -> None:
    value = json.loads(json.dumps(document))
    proof = value["proof_bytes_hex"]
    replacement = "0" if proof[0] != "0" else "1"
    value["proof_bytes_hex"] = replacement + proof[1:]
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


CPU_FALLBACK_COUNTERS = {
    "host_merkle_commits", "cpu_small_merkle_commits", "cpu_streaming_merkle_commits",
    "cpu_sampled_value_evaluations", "cpu_small_circle_interpolations",
    "cpu_small_circle_evaluations", "cpu_small_circle_ldes",
}


def _backend_honesty(cpu: dict[str, Any], metal: dict[str, Any]) -> dict[str, Any]:
    if (
        cpu.get("backend") != "cpu_native"
        or cpu.get("runtime_admission") is not None
        or cpu.get("backend_telemetry") is not None
        or cpu.get("profiled") is not False
        or cpu.get("evidence_class") != "correctness_only"
    ):
        raise CorrectnessError("CPU production report backend identity drifted")
    admission = metal.get("runtime_admission")
    telemetry = metal.get("backend_telemetry")
    if (
        metal.get("backend") != "metal_hybrid"
        or metal.get("profiled") is not False
        or metal.get("evidence_class") != "correctness_only"
        or not isinstance(admission, dict)
        or admission.get("initialized") is not True
        or admission.get("initialization_count") != 1
        or not isinstance(telemetry, dict)
        or telemetry.get("valid") is not True
        or not isinstance(telemetry.get("total_metal_dispatches"), int)
        or telemetry["total_metal_dispatches"] <= 0
        or telemetry.get("total_cpu_fallbacks") != 0
        or telemetry.get("warmups") != []
        or not isinstance(telemetry.get("samples"), list)
        or len(telemetry["samples"]) != 1
    ):
        raise CorrectnessError("Metal production report lacks device-only admission")
    sample = telemetry["samples"][0]
    counters = sample.get("counters") if isinstance(sample, dict) else None
    if (
        not isinstance(sample, dict)
        or sample.get("classification") != "accelerated_without_fallbacks"
        or not isinstance(sample.get("metal_dispatches"), int)
        or sample["metal_dispatches"] <= 0
        or sample.get("cpu_fallbacks") != 0
        or not isinstance(counters, dict)
        or not CPU_FALLBACK_COUNTERS.issubset(counters)
        or any(counters[name] != 0 for name in CPU_FALLBACK_COUNTERS)
    ):
        raise CorrectnessError("Metal production report contains CPU fallback activity")
    return {
        "runtime_initialized": True,
        "metal_dispatches_positive": True,
        "cpu_fallbacks_zero": True,
    }


def _publish(output: Path, value: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise CorrectnessError(
                "refusing to replace Native Metal correctness receipt"
            ) from error
    finally:
        temporary.unlink(missing_ok=True)


def check(
    cpu_cli: Path, metal_cli: Path, rust: Path, output: Path, root: Path,
) -> dict[str, Any]:
    cpu_cli = _binary(cpu_cli, "focused Native CPU prover")
    metal_cli = _binary(metal_cli, "focused Native Metal prover")
    rust = _binary(rust, "Native Rust oracle")
    root = root.resolve(strict=True)
    inherited = sorted(name for name in os.environ if name.startswith("STWO_ZIG_METAL_PROFILE"))
    if inherited:
        raise CorrectnessError("correctness gate refuses profiler environment")
    with tempfile.TemporaryDirectory(prefix="stwo-native-metal-correctness-") as directory:
        work = Path(directory)
        cpu_path = work / "cpu.json"
        metal_path = work / "metal.json"
        cpu_report_path = work / "cpu-report.json"
        metal_report_path = work / "metal-report.json"
        mutated_path = work / "mutated.json"
        cpu_document, cpu_report, cpu_proof = _prove_cpu(
            cpu_cli, cpu_path, cpu_report_path, root,
        )
        metal_document, metal_report, metal_proof = _prove_metal(
            metal_cli, cpu_cli, metal_path, metal_report_path, root,
        )
        if cpu_document != metal_document or cpu_proof != metal_proof:
            raise CorrectnessError("Native CPU and Metal proof artifacts differ")
        backend = _backend_honesty(cpu_report, metal_report)
        _oracle(rust, cpu_path, root, accepted=True)
        _oracle(rust, metal_path, root, accepted=True)
        _mutate(metal_document, mutated_path)
        _oracle(rust, mutated_path, root, accepted=False)
        receipt = {
            "schema": "build-architecture-native-metal-correctness-v1",
            "status": "PASS",
            "workload": {
                "air": "wide_fibonacci", "log_n_rows": 8, "sequence_len": 8,
                "protocol": "smoke",
            },
            "proof": {
                "cpu_artifact_sha256": hashlib.sha256(cpu_path.read_bytes()).hexdigest(),
                "metal_artifact_sha256": hashlib.sha256(metal_path.read_bytes()).hexdigest(),
                "proof_sha256": cpu_proof,
                "byte_identical": True,
            },
            "oracle": {
                "binary_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(),
                "cpu_accepted": True,
                "metal_accepted": True,
                "mutation_rejected": True,
            },
            "backend": backend,
        }
    _publish(output, receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu-cli", type=Path, required=True)
    parser.add_argument("--metal-cli", type=Path, required=True)
    parser.add_argument("--rust-oracle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        check(args.cpu_cli, args.metal_cli, args.rust_oracle, args.output, args.root)
    except (OSError, subprocess.TimeoutExpired, CorrectnessError, ValueError) as error:
        print(f"Native Metal correctness: FAIL: {error}", file=sys.stderr)
        return 2
    print("Native Metal correctness: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
