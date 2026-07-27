"""Adapter materialization, tool discovery, and receipt utility boundary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ADAPTER_DIR = ROOT / "conformance" / "riscv" / "arch-test"
EXPECTED_SUITES = ("I", "M")
EXPECTED_SOURCE_DIRS = tuple(Path("rv32i") / suite for suite in EXPECTED_SUITES)
LLVM_CANDIDATES = (
    Path("/opt/homebrew/opt/llvm/bin/clang"),
    Path("/usr/local/opt/llvm/bin/clang"),
)
LLD_BIN_DIR_CANDIDATES = (
    Path("/opt/homebrew/opt/lld/bin"),
    Path("/usr/local/opt/lld/bin"),
)


class ArchTestError(RuntimeError):
    """The architectural-test source, adapter, or result is not trustworthy."""


def resolve_llvm_nm() -> Path:
    candidates = [
        Path("/opt/homebrew/opt/llvm/bin/llvm-nm"),
        Path("/usr/local/opt/llvm/bin/llvm-nm"),
    ]
    found = shutil.which("llvm-nm")
    if found is not None:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ArchTestError("llvm-nm was not found (Homebrew: `brew install llvm`)")


def run_json(
    command: list[str],
    label: str,
    timeout: int = 120,
) -> dict[str, Any]:
    completed = run_checked(command, label=label, timeout=timeout)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ArchTestError(f"{label}: output is not JSON: {error}") from error
    if not isinstance(value, dict):
        raise ArchTestError(f"{label}: JSON root is not an object")
    return value


def run_checked(
    command: list[str],
    *,
    label: str,
    stdout: int | None = subprocess.PIPE,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdout=stdout,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if completed.returncode != 0:
        output = completed.stderr[-4000:].decode(errors="replace")
        raise ArchTestError(f"{label} failed ({completed.returncode}):\n{output}")
    return completed


def load_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArchTestError(f"{label}: cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise ArchTestError(f"{label}: JSON root is not an object")
    return value


def json_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ArchTestError(f"{label} is not a lowercase SHA-256 digest")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ArchTestError(f"{label} is not a lowercase SHA-256 digest") from error
    if decoded.hex() != value:
        raise ArchTestError(f"{label} is not a lowercase SHA-256 digest")
    return value


def materialize_adapter(
    destination: Path,
    arch_source: Path,
    paths: Any,
    profile: Any,
    clang: Path,
) -> None:
    for name in (
        "riscv_arch_test.h",
        "rvtest_config.h",
        "rvmodel_macros.h",
        "link.ld",
    ):
        shutil.copy2(ADAPTER_DIR / name, destination / name)

    default = subprocess.run(
        [str(paths.sail_binary), "--rv32", "--print-default-config"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    try:
        import pyjson5

        sail_config = pyjson5.decode(default)
    except (ImportError, ValueError) as error:
        raise ArchTestError(f"cannot decode pinned Sail default config: {error}") from error
    for override_path in profile.sail_overrides:
        override = json.loads(override_path.read_text(encoding="utf-8"))
        deep_merge(sail_config, override)
    sail_config_path = destination / "sail.json"
    sail_config_path.write_text(
        json.dumps(sail_config, indent=2) + "\n",
        encoding="utf-8",
    )
    validation = subprocess.run(
        [str(paths.sail_binary), "--config", str(sail_config_path), "--validate-config"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    if " is valid." not in validation.stdout + validation.stderr:
        raise ArchTestError("merged ACT4 Sail configuration did not validate")
    isa = subprocess.run(
        [str(paths.sail_binary), "--config", str(sail_config_path), "--print-isa-string"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if isa != "rv32im":
        raise ArchTestError(f"merged ACT4 Sail ISA is {isa!r}, expected 'rv32im'")

    config = {
        "name": "stwo-rv32im-zkvm",
        "compiler_exe": str(clang),
        "ref_model_exe": str(paths.sail_binary.resolve()),
        "udb_config": str(
            arch_source / "config" / "sail" / "sail-RVI20U32" / "sail-RVI20U32.yaml"
        ),
        "linker_script": str(destination / "link.ld"),
        "dut_include_dir": str(destination),
        "include_priv_tests": False,
    }
    # JSON is valid YAML and avoids depending on a second serializer.
    (destination / "test_config.yaml").write_text(
        json.dumps(config, indent=2) + "\n",
        encoding="utf-8",
    )


def expected_sources(arch_source: Path) -> set[Path]:
    tests = arch_source / "tests"
    return {
        source.resolve()
        for suite in EXPECTED_SOURCE_DIRS
        for source in (tests / suite).glob("*.S")
    }


def resolve_riscv_clang() -> Path:
    candidates = [*LLVM_CANDIDATES]
    found = shutil.which("clang")
    if found is not None:
        candidates.append(Path(found))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            version = subprocess.run(
                [str(resolved), "-dumpversion"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            targets = subprocess.run(
                [str(resolved), "--print-targets"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if int(version.split(".", 1)[0]) >= 20 and "riscv32" in targets:
            return resolved
    raise ArchTestError(
        "Clang 20+ with the riscv32 target was not found "
        "(Homebrew: `brew install llvm lld`)"
    )


def prepend_tool_paths(clang: Path) -> None:
    paths = [str(clang.parent)]
    for candidate in LLD_BIN_DIR_CANDIDATES:
        if (candidate / "ld.lld").is_file():
            paths.append(str(candidate))
            break
    else:
        if shutil.which("ld.lld") is None:
            raise ArchTestError("ld.lld was not found (Homebrew: `brew install lld`)")
    os.environ["PATH"] = os.pathsep.join(paths + [os.environ.get("PATH", "")])


def deep_merge(target: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = value


def adapter_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted(ADAPTER_DIR.iterdir()):
        if path.is_file():
            digest.update(path.name.encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
