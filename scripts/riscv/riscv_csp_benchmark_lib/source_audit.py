"""Source-isolated regeneration audit for the pinned CSP workload fixtures."""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.riscv_csp_benchmark_lib.contract import (
    BenchmarkError,
    TARGET_ORDER,
    repo_path,
    sha256_file,
)


def _run(
    argv: Sequence[str | Path],
    *,
    cwd: Path | None = None,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    command = [str(item) for item in argv]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BenchmarkError(f"command failed to run: {command!r}: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        raise BenchmarkError(
            f"command failed ({completed.returncode}): {command!r}: {stderr}"
        )
    return completed


def _git_output(source: Path, *args: str) -> str:
    return _run(["git", *args], cwd=source, timeout=30).stdout.decode().strip()


def _compile_fixture_dump(
    manifest: Mapping[str, Any],
    source: Path,
    output: Path,
) -> Path:
    adapter = manifest["upstream"]["extended_input_adapter"]
    adapter_path = repo_path(adapter["path"], "CSP extended input adapter path")
    if sha256_file(adapter_path) != adapter["sha256"]:
        raise BenchmarkError("CSP extended input adapter drifted")
    library = source / "target" / "release" / "libutils.rlib"
    dependencies = source / "target" / "release" / "deps"
    if not library.is_file() or not dependencies.is_dir():
        raise BenchmarkError(
            "CSP utility library is missing; run "
            "`cargo build --release --locked -p utils` inside the pinned checkout"
        )
    channel = manifest["upstream"]["rust_toolchain"]["channel"]
    _run(
        [
            "rustc",
            f"+{channel}",
            "--edition=2024",
            adapter_path,
            "-L",
            f"dependency={dependencies}",
            "--extern",
            f"utils={library}",
            "-o",
            output,
        ],
        timeout=120,
    )
    if not output.is_file() or not os.access(output, os.X_OK):
        raise BenchmarkError("CSP extended input adapter was not produced")
    return output


def _decode_lines(
    completed: subprocess.CompletedProcess[bytes],
    *,
    expected: int,
    label: str,
) -> list[str]:
    try:
        lines = completed.stdout.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise BenchmarkError(f"{label} emitted non-ASCII output") from error
    if len(lines) != expected:
        raise BenchmarkError(f"{label} output drifted")
    return lines


def _regenerate_case(
    *,
    target: str,
    size: int,
    utilities: Path,
    extended: Path,
    source: Path,
    expected_digest: str,
) -> tuple[bytes, str]:
    if target in {"sha256", "keccak"}:
        lines = _decode_lines(
            _run(
                [utilities, target, "--size", str(size)],
                cwd=source,
                timeout=60,
            ),
            expected=2,
            label=f"CSP utility {target}/{size}",
        )
        try:
            return struct.pack("<I", size) + bytes.fromhex(lines[0]), lines[1]
        except ValueError as error:
            raise BenchmarkError(
                f"CSP utility emitted invalid input for {target}/{size}"
            ) from error
    if target == "poseidon2_m31":
        lines = _decode_lines(
            _run([extended, "poseidon2-m31", str(size)], timeout=60),
            expected=1,
            label=f"CSP M31 adapter {target}/{size}",
        )
        try:
            return bytes.fromhex(lines[0]), expected_digest
        except ValueError as error:
            raise BenchmarkError("CSP M31 adapter emitted invalid hex") from error
    if target == "ecdsa_secp256k1":
        lines = _decode_lines(
            _run([extended, "ecdsa-secp256k1"], timeout=60),
            expected=2,
            label="CSP k256 adapter",
        )
        try:
            return bytes.fromhex(lines[0]), lines[1]
        except ValueError as error:
            raise BenchmarkError("CSP k256 adapter emitted invalid hex") from error
    raise BenchmarkError(f"no source audit for target {target}")


def _validate_source_bindings(
    manifest: Mapping[str, Any],
    source: Path,
) -> int:
    upstream = manifest["upstream"]
    bound_files = [
        upstream["input_generator"],
        upstream["size_metadata"],
        upstream["rust_toolchain"],
    ]
    for target in TARGET_ORDER:
        guest = manifest["targets"][target]["guest"]
        if guest["source_repository"] == "csp_upstream":
            bound_files.extend(guest["source_files"])
    for binding in bound_files:
        path = (source / binding["path"]).resolve()
        try:
            path.relative_to(source)
        except ValueError as error:
            raise BenchmarkError("CSP source binding escapes its checkout") from error
        if not path.is_file() or sha256_file(path) != binding["sha256"]:
            raise BenchmarkError(f"CSP source binding drifted: {binding['path']}")
    return len(bound_files)


def audit_csp_source(
    manifest: Mapping[str, Any],
    source: Path,
) -> dict[str, Any]:
    source = source.resolve()
    if not (source / ".git").exists():
        raise BenchmarkError(f"CSP source is not a Git checkout: {source}")
    expected_commit = manifest["upstream"]["commit"]
    actual_commit = _git_output(source, "rev-parse", "HEAD")
    if actual_commit != expected_commit:
        raise BenchmarkError(
            f"CSP source is {actual_commit}, expected pinned {expected_commit}"
        )
    if _git_output(source, "status", "--short"):
        raise BenchmarkError("CSP source checkout is dirty")
    bound_file_count = _validate_source_bindings(manifest, source)

    utilities = source / "target" / "release" / "utils"
    if not utilities.is_file():
        raise BenchmarkError(
            "CSP utility is missing; run `cargo build --release --locked -p utils` "
            "inside the pinned checkout"
        )
    regenerated: dict[Path, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="stwo-csp-upstream-adapter-") as raw:
        extended = _compile_fixture_dump(
            manifest,
            source,
            Path(raw) / "fixture-dump",
        )
        for target in TARGET_ORDER:
            for case in manifest["targets"][target]["cases"]:
                size = case["input_size"]
                vm_input, expected_digest = _regenerate_case(
                    target=target,
                    size=size,
                    utilities=utilities,
                    extended=extended,
                    source=source,
                    expected_digest=case["expected_digest"],
                )
                expected_file = repo_path(case["input_path"], "CSP input path")
                if vm_input != expected_file.read_bytes():
                    raise BenchmarkError(
                        f"CSP input fixture drifted for {target}/{size}"
                    )
                if expected_digest != case["expected_digest"]:
                    raise BenchmarkError(
                        f"CSP expected digest drifted for {target}/{size}"
                    )
                prior = regenerated.setdefault(expected_file, vm_input)
                if prior != vm_input:
                    raise BenchmarkError(
                        f"CSP targets generated different bytes for {expected_file}"
                    )

        for negative in manifest["negative_fixtures"]:
            valid_path = repo_path(
                manifest["targets"]["ecdsa_secp256k1"]["cases"][0]["input_path"],
                "CSP ECDSA input path",
            )
            invalid = bytearray(regenerated[valid_path])
            invalid[-1] ^= 1
            invalid_path = repo_path(
                negative["input_path"],
                "CSP negative input path",
            )
            if bytes(invalid) != invalid_path.read_bytes():
                raise BenchmarkError(
                    f"CSP negative fixture drifted: {negative['name']}"
                )
    return {
        "status": "passed",
        "source": str(source),
        "commit": actual_commit,
        "bound_file_count": bound_file_count,
        "regenerated_input_count": len(regenerated),
        "negative_fixture_count": len(manifest["negative_fixtures"]),
    }
