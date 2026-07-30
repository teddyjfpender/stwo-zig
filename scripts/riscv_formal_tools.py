#!/usr/bin/env python3
"""Prepare and verify the exact external tools for RV32IM conformance.

The command owns no floating branches. It checks out the Sail model, Spike,
and riscv-arch-test at the revisions in the machine-readable formal profile,
applies the hash-pinned RVFI harness patch, and builds the two executors.

Examples:

  python3 scripts/riscv_formal_tools.py prepare --workspace /tmp/riscv-formal
  python3 scripts/riscv_formal_tools.py verify  --workspace /tmp/riscv-formal

The workspace is caller-selected and may be cached. Existing checkouts are
accepted only when their source identity and complete working-tree state are
exactly the state this command would produce.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PROFILE_PATH = ROOT / "conformance" / "riscv" / "rv32im-sail-profile.json"
SAIL_PATCHED_SOURCE = Path("c_emulator/rvfi_dii.cpp")
SAIL_BINARY = Path("build/c_emulator/sail_riscv_sim")
SPIKE_BINARY = Path("install/bin/spike")
SPIKE_IDENTITY_PREFIX = "Spike RISC-V ISA Simulator "


class FormalToolsError(RuntimeError):
    """A formal-tool checkout, build, or identity is not trustworthy."""


@dataclasses.dataclass(frozen=True)
class Authority:
    repository: str
    revision: str


@dataclasses.dataclass(frozen=True)
class FormalProfile:
    name: str
    sail: Authority
    sail_tag: str
    sail_compiler: str
    sail_overrides: tuple[Path, ...]
    spike: Authority
    arch_test: Authority
    rvfi_entry: int
    rvfi_patch: Path
    rvfi_patch_sha256: str


@dataclasses.dataclass(frozen=True)
class ToolPaths:
    workspace: Path

    @property
    def sail_source(self) -> Path:
        return self.workspace / "source" / "sail-riscv"

    @property
    def spike_source(self) -> Path:
        return self.workspace / "source" / "riscv-isa-sim"

    @property
    def arch_test_source(self) -> Path:
        return self.workspace / "source" / "riscv-arch-test"

    @property
    def sail_binary(self) -> Path:
        return self.sail_source / SAIL_BINARY

    @property
    def spike_build(self) -> Path:
        return self.workspace / "build" / "spike"

    @property
    def spike_prefix(self) -> Path:
        return self.workspace / "install" / "spike"

    @property
    def spike_binary(self) -> Path:
        return self.spike_prefix / "bin" / "spike"


def load_profile(path: Path = PROFILE_PATH) -> FormalProfile:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FormalToolsError(f"{path}: cannot read formal profile: {error}") from error
    try:
        if value["schema"] != "stwo-riscv-formal-profile-v1":
            raise KeyError("schema")
        authorities = value["authorities"]
        sail = authorities["sail"]
        spike = authorities["spike"]
        arch_test = authorities["riscv_arch_test"]
        transport = value["rvfi_transport"]
        patch = transport["patch"]
        overrides = tuple(ROOT / item for item in sail["configuration_overrides_in_order"])
        result = FormalProfile(
            name=value["name"],
            sail=Authority(sail["repository"], sail["revision"]),
            sail_tag=sail["tag"],
            sail_compiler=sail["compiler"],
            sail_overrides=overrides,
            spike=Authority(spike["repository"], spike["revision"]),
            arch_test=Authority(arch_test["repository"], arch_test["revision"]),
            rvfi_entry=transport["entry_point"],
            rvfi_patch=ROOT / patch["path"],
            rvfi_patch_sha256=patch["sha256"],
        )
    except (KeyError, TypeError) as error:
        raise FormalToolsError(f"{path}: incomplete formal profile ({error})") from error
    if result.name != "rv32im-zkvm-v1" or result.rvfi_entry != 0x0001_0000:
        raise FormalToolsError(f"{path}: unsupported formal profile")
    if any(not override.is_file() for override in result.sail_overrides):
        raise FormalToolsError(f"{path}: a Sail configuration override is missing")
    if _sha256_file(result.rvfi_patch) != result.rvfi_patch_sha256:
        raise FormalToolsError(f"{result.rvfi_patch}: transport patch SHA-256 drift")
    return result


def ensure_checkout(path: Path, authority: Authority) -> None:
    """Materialize one detached, exact, clean Git checkout."""
    if path.exists() and not (path / ".git").exists():
        raise FormalToolsError(f"{path}: exists but is not a Git checkout")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        _run(("git", "init", str(path)))
        _run(("git", "-C", str(path), "remote", "add", "origin", authority.repository))

    remote = _output(("git", "-C", str(path), "remote", "get-url", "origin"))
    if _canonical_repository(remote) != _canonical_repository(authority.repository):
        raise FormalToolsError(
            f"{path}: origin is {remote!r}, expected {authority.repository!r}"
        )
    status = _output(("git", "-C", str(path), "status", "--porcelain"))
    if status:
        raise FormalToolsError(f"{path}: checkout is dirty before pinning")
    head = _optional_output(("git", "-C", str(path), "rev-parse", "HEAD"))
    if head != authority.revision:
        _run(
            (
                "git",
                "-C",
                str(path),
                "fetch",
                "--depth=1",
                "origin",
                authority.revision,
            )
        )
        _run(("git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD"))
    _require_head(path, authority.revision)
    _require_clean(path)


def ensure_patched_sail(path: Path, profile: FormalProfile) -> None:
    """Apply or validate the one allowed Sail harness modification."""
    _require_head(path, profile.sail.revision)
    status = _output(("git", "-C", str(path), "status", "--porcelain"))
    if not status:
        _run(("git", "-C", str(path), "apply", "--check", str(profile.rvfi_patch)))
        _run(("git", "-C", str(path), "apply", str(profile.rvfi_patch)))

    # `_output` strips surrounding whitespace, including Git's leading
    # worktree-status column.
    expected_status = f"M {SAIL_PATCHED_SOURCE.as_posix()}"
    status = _output(("git", "-C", str(path), "status", "--porcelain"))
    if status != expected_status:
        raise FormalToolsError(
            f"{path}: patched Sail status is {status!r}, expected {expected_status!r}"
        )
    _run(
        (
            "git",
            "-C",
            str(path),
            "apply",
            "--reverse",
            "--check",
            str(profile.rvfi_patch),
        )
    )
    upstream = _output_bytes(
        (
            "git",
            "-C",
            str(path),
            "show",
            f"HEAD:{SAIL_PATCHED_SOURCE.as_posix()}",
        )
    )
    old = b"  return 0x80000000;"
    new = b"  return 0x00010000;"
    if upstream.count(old) != 1 or new in upstream:
        raise FormalToolsError(f"{path}: pinned Sail RVFI source shape drifted")
    expected = upstream.replace(old, new)
    if (path / SAIL_PATCHED_SOURCE).read_bytes() != expected:
        raise FormalToolsError(f"{path}: Sail checkout contains changes beyond the RVFI patch")


def resolve_sail_compiler(explicit: Path | None, expected_version: str) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    found = shutil.which("sail")
    if found is not None:
        candidates.append(Path(found))
    opam_bin = _optional_output(("opam", "var", "bin"))
    if opam_bin:
        candidates.append(Path(opam_bin) / "sail")

    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
            version = _output((str(resolved), "--version"))
        except (OSError, FormalToolsError):
            continue
        if re.search(rf"\bSail {re.escape(expected_version)}(?:\s|$)", version):
            return resolved
    raise FormalToolsError(
        f"Sail compiler {expected_version} was not found; pass --sail-compiler"
    )


def require_device_tree_compiler() -> Path:
    """Fail before long builds when Spike's required DTS compiler is absent."""
    found = shutil.which("dtc")
    if found is None:
        raise FormalToolsError(
            "Spike requires the device-tree compiler `dtc`; install it first "
            "(for example, `brew install dtc` on macOS)"
        )
    binary = Path(found).resolve()
    version = _output((str(binary), "--version"))
    if re.fullmatch(r"(?:Version: DTC|Device Tree Compiler version) \d+\.\d+\.\d+", version) is None:
        raise FormalToolsError(f"{binary}: unexpected device-tree compiler identity")
    return binary


def build_clean_sail(
    paths: ToolPaths,
    compiler: Path,
    jobs: int,
    download_gmp: bool,
) -> None:
    env = os.environ.copy()
    env["PATH"] = str(compiler.parent) + os.pathsep + env.get("PATH", "")
    _run(
        (
            "cmake",
            "-S",
            str(paths.sail_source),
            "-B",
            str(paths.sail_source / "build"),
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            f"-DDOWNLOAD_GMP={'TRUE' if download_gmp else 'FALSE'}",
            "-DENABLE_RISCV_TESTS=FALSE",
        ),
        env=env,
        cwd=paths.sail_source,
    )
    _run(
        (
            "cmake",
            "--build",
            str(paths.sail_source / "build"),
            "--target",
            "sail_riscv_sim",
            "--parallel",
            str(jobs),
        ),
        env=env,
    )


def prepare_sail(
    paths: ToolPaths,
    profile: FormalProfile,
    compiler: Path,
    jobs: int,
    download_gmp: bool,
) -> None:
    """Build identity from clean source, then apply and compile the harness patch."""
    was_patched = False
    if paths.sail_source.exists():
        _require_head(paths.sail_source, profile.sail.revision)
        status = _output(
            ("git", "-C", str(paths.sail_source), "status", "--porcelain")
        )
        if status:
            ensure_patched_sail(paths.sail_source, profile)
            was_patched = True
    else:
        ensure_checkout(paths.sail_source, profile.sail)

    _run(
        (
            "git",
            "-C",
            str(paths.sail_source),
            "fetch",
            "--depth=1",
            "origin",
            f"refs/tags/{profile.sail_tag}:refs/tags/{profile.sail_tag}",
        )
    )
    tag_revision = _output(
        ("git", "-C", str(paths.sail_source), "rev-list", "-n1", profile.sail_tag)
    )
    if tag_revision != profile.sail.revision:
        raise FormalToolsError(
            f"{paths.sail_source}: tag {profile.sail_tag} points to {tag_revision}, "
            f"expected {profile.sail.revision}"
        )

    if was_patched:
        _run(
            (
                "git",
                "-C",
                str(paths.sail_source),
                "apply",
                "--reverse",
                str(profile.rvfi_patch),
            )
        )
    try:
        _require_clean(paths.sail_source)
        build_clean_sail(paths, compiler, jobs, download_gmp)
    finally:
        # Even a failed external build must leave the dependency in the
        # repository-declared patched state for inspection and retry.
        status = _output(
            ("git", "-C", str(paths.sail_source), "status", "--porcelain")
        )
        if not status:
            _run(
                (
                    "git",
                    "-C",
                    str(paths.sail_source),
                    "apply",
                    str(profile.rvfi_patch),
                )
            )

    env = os.environ.copy()
    env["PATH"] = str(compiler.parent) + os.pathsep + env.get("PATH", "")
    _run(
        (
            "cmake",
            "--build",
            str(paths.sail_source / "build"),
            "--target",
            "sail_riscv_sim",
            "--parallel",
            str(jobs),
        ),
        env=env,
    )
    verify_sail(paths, profile)


def verify_sail(paths: ToolPaths, profile: FormalProfile) -> None:
    ensure_patched_sail(paths.sail_source, profile)
    binary = paths.sail_binary.resolve(strict=True)
    info = _output((str(binary), "--build-info"))
    for expected in (
        f"Sail RISC-V git: {profile.sail_tag}",
        f"Sail: Sail {profile.sail_compiler} ",
    ):
        if expected not in info:
            raise FormalToolsError(f"{binary}: missing build identity {expected!r}")
    command = [str(binary), "--rv32"]
    for override in profile.sail_overrides:
        command.extend(("--config-override", str(override)))
    command.append("--validate-config")
    validation = _output(tuple(command))
    if "Default configuration is valid." not in validation:
        raise FormalToolsError(f"{binary}: Sail configuration did not validate")


def build_spike(paths: ToolPaths, jobs: int) -> None:
    _require_clean(paths.spike_source)
    paths.spike_build.mkdir(parents=True, exist_ok=True)
    paths.spike_prefix.mkdir(parents=True, exist_ok=True)
    configure = paths.spike_source / "configure"
    if not configure.is_file():
        raise FormalToolsError(f"{configure}: pinned Spike configure script is missing")
    _run(
        (
            str(configure),
            f"--prefix={paths.spike_prefix}",
            "--with-boost=no",
        ),
        cwd=paths.spike_build,
    )
    _run(("make", f"-j{jobs}"), cwd=paths.spike_build)
    _run(("make", "install"), cwd=paths.spike_build)
    verify_spike(paths)


def verify_spike(paths: ToolPaths) -> None:
    _require_clean(paths.spike_source)
    binary = paths.spike_binary.resolve(strict=True)
    # This pinned Spike predates `--version`; its stable identity banner is
    # emitted by `--help`, which exits successfully.
    help_text = _output((str(binary), "--help"))
    _validate_spike_identity(binary, help_text)


def _validate_spike_identity(binary: Path, help_text: str) -> None:
    if not help_text.startswith(SPIKE_IDENTITY_PREFIX):
        raise FormalToolsError(f"{binary}: unexpected Spike identity")


def prepare(
    paths: ToolPaths,
    profile: FormalProfile,
    compiler: Path,
    jobs: int,
    download_gmp: bool,
) -> dict[str, Any]:
    # Spike's configure/build consumes dtc. Check this before spending time on
    # the independent Sail build so a missing host dependency fails fast.
    require_device_tree_compiler()
    prepare_sail(paths, profile, compiler, jobs, download_gmp)
    ensure_checkout(paths.spike_source, profile.spike)
    ensure_checkout(paths.arch_test_source, profile.arch_test)
    build_spike(paths, jobs)
    return receipt(paths, profile, compiler)


def verify(
    paths: ToolPaths,
    profile: FormalProfile,
    compiler: Path,
) -> dict[str, Any]:
    _require_head(paths.sail_source, profile.sail.revision)
    _require_head(paths.spike_source, profile.spike.revision)
    _require_head(paths.arch_test_source, profile.arch_test.revision)
    _require_clean(paths.spike_source)
    _require_clean(paths.arch_test_source)
    verify_sail(paths, profile)
    verify_spike(paths)
    return receipt(paths, profile, compiler)


def receipt(
    paths: ToolPaths,
    profile: FormalProfile,
    compiler: Path,
) -> dict[str, Any]:
    return {
        "schema": "stwo-riscv-formal-tools-v1",
        "profile": profile.name,
        "profile_sha256": _sha256_file(PROFILE_PATH),
        "sail": {
            "revision": profile.sail.revision,
            "compiler": profile.sail_compiler,
            "compiler_path": str(compiler),
            "transport_patch_sha256": profile.rvfi_patch_sha256,
            "binary": str(paths.sail_binary.resolve()),
            "binary_sha256": _sha256_file(paths.sail_binary),
        },
        "spike": {
            "revision": profile.spike.revision,
            "binary": str(paths.spike_binary.resolve()),
            "binary_sha256": _sha256_file(paths.spike_binary),
        },
        "riscv_arch_test": {
            "revision": profile.arch_test.revision,
            "source": str(paths.arch_test_source.resolve()),
        },
    }


def _require_head(path: Path, expected: str) -> None:
    head = _optional_output(("git", "-C", str(path), "rev-parse", "HEAD"))
    if head != expected:
        raise FormalToolsError(f"{path}: HEAD is {head!r}, expected {expected}")


def _require_clean(path: Path) -> None:
    status = _output(("git", "-C", str(path), "status", "--porcelain"))
    if status:
        raise FormalToolsError(f"{path}: checkout is dirty")


def _canonical_repository(value: str) -> str:
    return value.removesuffix("/").removesuffix(".git")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    command: tuple[str, ...],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    try:
        # Keep stdout machine-readable: compiler and build progress belongs on
        # stderr, while the final verified receipt is the sole stdout payload.
        subprocess.run(
            command,
            cwd=cwd or ROOT,
            env=env,
            check=True,
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise FormalToolsError(f"{' '.join(command)} failed: {error}") from error


def _output(
    command: tuple[str, ...],
    *,
    cwd: Path | None = None,
) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd or ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise FormalToolsError(f"{' '.join(command)} failed: {error}") from error
    return (result.stdout + result.stderr).strip()


def _output_bytes(command: tuple[str, ...]) -> bytes:
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise FormalToolsError(f"{' '.join(command)} failed: {error}") from error


def _optional_output(command: tuple[str, ...]) -> str | None:
    try:
        return _output(command)
    except FormalToolsError:
        return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="dedicated source/build/install directory",
    )
    parser.add_argument("--sail-compiler", type=Path)
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument(
        "--system-gmp",
        action="store_true",
        help="link a system GMP instead of Sail's pinned download",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.jobs <= 0:
            raise FormalToolsError("--jobs must be positive")
        profile = load_profile()
        compiler = resolve_sail_compiler(args.sail_compiler, profile.sail_compiler)
        paths = ToolPaths(args.workspace.expanduser().resolve())
        if args.command == "prepare":
            result = prepare(
                paths,
                profile,
                compiler,
                args.jobs,
                not args.system_gmp,
            )
        else:
            result = verify(paths, profile, compiler)
    except (FormalToolsError, OSError) as error:
        print(f"riscv formal tools: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
