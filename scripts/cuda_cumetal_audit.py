#!/usr/bin/env python3
"""Audit CuMetal translation status and exact Apple-GPU execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from cuda_build_lib.cumetal_toolchain import (
    CuMetalToolchainError,
    verify_checkout,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = ROOT / "conformance/cuda-cumetal-compatibility-v1.json"
TRANSLATED = {"translated", "translated_host_parity_bitreverse"}
BLOCKERS = {
    "blocked_bitreverse",
    "blocked_funnel_shift",
    "blocked_shared_atomic",
    "blocked_cub",
    "blocked_u64_atomic_min",
    "blocked_runtime_api",
}
BLOCKER_PATTERNS = {
    "blocked_bitreverse": "unsupported call target '__nv_brev'",
    "blocked_funnel_shift": "shf.l.wrap.b32",
    "blocked_shared_atomic": "atom.shared.exch.b32",
    "blocked_cub": "cub/cub.cuh",
    "blocked_u64_atomic_min": "no matching function for call to 'atomicMin'",
    "blocked_runtime_api": "use of undeclared identifier 'cudaError",
}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AuditError(RuntimeError):
    pass


def read_ledger(path: Path) -> dict[str, object]:
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read CuMetal ledger: {error}") from error
    probes = ledger.get("probes")
    execution = ledger.get("execution")
    if (
        ledger.get("schema") != "stwo-zig-cumetal-compatibility-v1"
        or ledger.get("audited_version") != "0.1.3"
        or SHA40.fullmatch(str(ledger.get("audited_commit", ""))) is None
        or not isinstance(probes, list)
        or len(probes) != 33
        or not isinstance(execution, list)
        or len(execution) != 1
    ):
        raise AuditError("CuMetal ledger header drifted")
    corpus = execution[0]
    if (
        not isinstance(corpus, dict)
        or set(corpus) != {"harness", "kernel", "label", "pass_marker"}
        or not isinstance(corpus.get("harness"), str)
        or not str(corpus["harness"]).startswith("tests/cuda/cumetal/")
        or not (ROOT / str(corpus["harness"])).is_file()
        or IDENTIFIER.fullmatch(str(corpus.get("kernel", ""))) is None
        or not isinstance(corpus.get("label"), str)
        or not isinstance(corpus.get("pass_marker"), str)
        or not corpus["pass_marker"]
    ):
        raise AuditError("CuMetal execution corpus is malformed")
    labels: set[str] = set()
    sources: set[str] = set()
    floor = 0
    strict = 0
    for probe in probes:
        if not isinstance(probe, dict):
            raise AuditError("CuMetal probe is malformed")
        label = probe.get("label")
        source = probe.get("source")
        expected = probe.get("expected")
        definitions = probe.get("definitions", [])
        if (
            not isinstance(label, str)
            or label in labels
            or not isinstance(source, str)
            or source in sources
            or not source.startswith("src/backends/cuda/native/")
            or not source.endswith(".cu")
            or expected not in TRANSLATED | BLOCKERS
            or not isinstance(definitions, list)
            or any(not isinstance(value, str) for value in definitions)
        ):
            raise AuditError("CuMetal probe identity is malformed")
        if not (ROOT / source).is_file():
            raise AuditError(f"CuMetal probe source is absent: {source}")
        labels.add(label)
        sources.add(source)
        floor += expected in TRANSLATED
        strict += expected == "translated"
    if (
        floor != ledger.get("positive_floor_count")
        or strict != ledger.get("strict_translation_count")
        or floor != 33
        or strict != 31
    ):
        raise AuditError("CuMetal positive floor drifted")
    maintained = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src/backends/cuda/native").rglob("*.cu")
        if path.is_file()
    }
    if sources != maintained:
        raise AuditError("CuMetal ledger does not cover the maintained CUDA closure")
    return ledger


def command(
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def compiler_identity(compiler: Path, ledger: dict[str, object]) -> dict[str, str]:
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise AuditError(f"CuMetal compiler is not executable: {compiler}")
    result = command([str(compiler), "--version"])
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0 or str(ledger["audited_version"]) not in output:
        raise AuditError(f"CuMetal version differs from the audited ledger: {output}")
    return {
        "version": output,
        "sha256": digest_file(compiler),
        "audited_commit": str(ledger["audited_commit"]),
    }


def translate(
    compiler: Path,
    probe: dict[str, object],
    directory: Path,
    inspect: Path | None,
    validate: Path | None,
) -> dict[str, object]:
    output = directory / f"{probe['label']}.metallib"
    arguments = [
        str(compiler),
        str(ROOT / str(probe["source"])),
        "-o",
        str(output),
        "--cuda-device",
        "--ptx-strict",
        "--overwrite",
        "-DSTWO_CUMETAL=1",
        "-I",
        str(ROOT / "src/backends/cuda/native"),
    ]
    for definition in probe.get("definitions", []):
        arguments.append(f"-D{definition}")
    result = command(arguments)
    combined = result.stdout + result.stderr
    translated = result.returncode == 0 and output.is_file()
    expected = str(probe["expected"])
    blocker_signature = (
        expected in BLOCKERS
        and not translated
        and BLOCKER_PATTERNS[expected] in combined
    )
    matches = translated if expected in TRANSLATED else blocker_signature
    receipt: dict[str, object] = {
        "label": probe["label"],
        "source": probe["source"],
        "source_sha256": digest_file(ROOT / str(probe["source"])),
        "expected": expected,
        "observed": (
            "translated"
            if translated
            else expected
            if blocker_signature
            else "translation_failed_unknown"
        ),
        "exit_code": result.returncode,
        "diagnostic_sha256": digest_text(combined),
        "matches_ledger": matches,
    }
    if expected in BLOCKERS:
        receipt["blocker_signature_matched"] = blocker_signature
    if translated:
        receipt["metallib_sha256"] = digest_file(output)
        for name, tool in (("air_inspect", inspect), ("air_validate", validate)):
            if tool is None:
                continue
            checked = command([str(tool), str(output)])
            receipt[f"{name}_exit_code"] = checked.returncode
            receipt[f"{name}_sha256"] = digest_text(
                checked.stdout + checked.stderr
            )
            if checked.returncode != 0:
                receipt["matches_ledger"] = False
    return receipt


def execute_corpus(
    compiler: Path,
    ledger: dict[str, object],
    directory: Path,
) -> list[dict[str, object]]:
    receipts: list[dict[str, object]] = []
    for entry in ledger["execution"]:
        assert isinstance(entry, dict)
        harness = ROOT / str(entry["harness"])
        executable = directory / str(entry["label"])
        compiled = command([str(compiler), str(harness), "-o", str(executable)])
        compile_output = compiled.stdout + compiled.stderr
        receipt: dict[str, object] = {
            "label": entry["label"],
            "harness": entry["harness"],
            "harness_sha256": digest_file(harness),
            "compile_exit_code": compiled.returncode,
            "compile_diagnostic_sha256": digest_text(compile_output),
            "passed": False,
        }
        if compiled.returncode == 0 and executable.is_file():
            environment = dict(os.environ)
            environment["CUMETAL_TRACE_GPU"] = "1"
            environment["CUMETAL_MSL_MATH_MODE"] = "safe"
            executed = command(
                [str(executable)],
                environment=environment,
                timeout=60,
            )
            output = executed.stdout + executed.stderr
            provenance = [
                line for line in output.splitlines()
                if line.startswith("CUMETAL_PROVENANCE")
            ]
            kernel = str(entry["kernel"])
            gpu = any(
                kernel in line
                and "device=apple_gpu" in line
                and "launch_success=true" in line
                for line in provenance
            )
            forbidden = any(
                "source=cpu_fallback" in line or "source=stub" in line
                for line in provenance
            )
            marker = str(entry["pass_marker"]) in output
            receipt.update(
                {
                    "execution_exit_code": executed.returncode,
                    "execution_output_sha256": digest_text(output),
                    "provenance_records": len(provenance),
                    "apple_gpu_launch": gpu,
                    "kernel_provenance": kernel,
                    "fallback_or_stub": forbidden,
                    "numerical_marker": marker,
                    "passed": executed.returncode == 0
                    and gpu
                    and not forbidden
                    and marker,
                }
            )
        receipts.append(receipt)
    return receipts


def write_receipt(path: Path | None, receipt: dict[str, object]) -> None:
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("check", "floor", "audit"), required=True)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--cumetal-root", type=Path)
    parser.add_argument(
        "--compat-patch",
        type=Path,
        default=ROOT / "src/backends/cuda/cumetal/patches/0001-stwo-aot-ptx.patch",
    )
    parser.add_argument("--air-inspect", type=Path)
    parser.add_argument("--air-validate", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    ledger_path = args.ledger.resolve()
    ledger = read_ledger(ledger_path)
    if args.mode == "check":
        write_receipt(
            args.receipt,
            {
                "schema": "stwo-zig-cumetal-ledger-check-v1",
                "ledger_sha256": digest_file(ledger_path),
                "probe_count": len(ledger["probes"]),
                "positive_floor_count": ledger["positive_floor_count"],
                "strict_translation_count": ledger["strict_translation_count"],
                "verdict": "pass",
            },
        )
        return 0
    if args.compiler is None:
        raise AuditError("CuMetal audit requires --compiler")
    if args.cumetal_root is None:
        raise AuditError("CuMetal audit requires --cumetal-root")
    if args.mode == "audit" and (
        args.air_inspect is None or args.air_validate is None
    ):
        raise AuditError("full CuMetal audit requires AIR inspect and validate tools")
    compiler = args.compiler.resolve()
    checkout_identity = verify_checkout(
        args.cumetal_root.resolve(),
        args.compat_patch.resolve(),
    )
    if checkout_identity["commit"] != ledger["audited_commit"]:
        raise AuditError("CuMetal ledger and patched checkout identity differ")
    identity = compiler_identity(compiler, ledger)
    selected = [
        probe
        for probe in ledger["probes"]
        if args.mode == "audit" or probe["expected"] in TRANSLATED
    ]
    with tempfile.TemporaryDirectory(prefix="stwo-cumetal-audit-") as temporary:
        directory = Path(temporary)
        results = [
            translate(
                compiler,
                probe,
                directory,
                args.air_inspect,
                args.air_validate,
            )
            for probe in selected
        ]
        executions = (
            execute_corpus(compiler, ledger, directory)
            if args.execute
            else []
        )
    passed = all(bool(result["matches_ledger"]) for result in results) and all(
        bool(result["passed"]) for result in executions
    )
    receipt = {
        "schema": "stwo-zig-cumetal-audit-receipt-v1",
        "mode": args.mode,
        "ledger_sha256": digest_file(ledger_path),
        "compiler": identity,
        "checkout": checkout_identity,
        "tools": {
            name: {"path": str(path.resolve()), "sha256": digest_file(path.resolve())}
            for name, path in (
                ("air_inspect", args.air_inspect),
                ("air_validate", args.air_validate),
            )
            if path is not None
        },
        "summary": {
            "probes": len(results),
            "translated": sum(result["observed"] == "translated" for result in results),
            "blocked": sum(result["expected"] in BLOCKERS for result in results),
            "executions": len(executions),
        },
        "results": results,
        "execution": executions,
        "verdict": "pass" if passed else "fail",
    }
    write_receipt(args.receipt, receipt)
    if not passed:
        raise AuditError("CuMetal results differ from the checked compatibility ledger")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, CuMetalToolchainError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"CuMetal audit rejected: {error}") from error
