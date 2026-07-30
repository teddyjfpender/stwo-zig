"""Fail-closed validation of the prover executable's compiled build identity.

Two binaries built minutes apart by different commands can differ in target
architecture or optimize mode with no signal in the report.  A Debug build
reports timings several times slower than ReleaseFast, and on macOS an x86_64
build still *runs* on an arm64 host under Rosetta 2 -- it neither crashes nor
announces itself, it is simply slow.  Either way the published numbers are
wrong and nothing in the evidence says so.

The product CLI already publishes its compiled target and optimize mode in the
same ``applications`` registry admission is derived from (see
``riscv_cli_admission.FOCUSED_PRODUCT_FIELDS``), so this module reads that
existing identity surface rather than opening a second provenance channel.
"""

from __future__ import annotations

import json
import platform
import subprocess
from pathlib import Path
from typing import Any, Mapping

from scripts.riscv_csp_benchmark_lib.contract import (
    BenchmarkError,
    MAX_CAPTURE_BYTES,
    _strict_object,
)


PUBLICATION_OPTIMIZE = "ReleaseFast"
IDENTITY_FIELDS = ("arch", "os", "abi", "cpu_model", "optimize")
# ``platform.machine()``/``platform.system()`` and the Zig target triple name
# the same host differently.  Only hosts this suite can actually run on are
# mapped, so an unrecognised host fails closed rather than being waved through
# on the assumption that the names happen to agree.
HOST_ARCHITECTURES = {
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "x86_64",
    "x86_64": "x86_64",
}
HOST_OPERATING_SYSTEMS = {
    "Darwin": "macos",
    "Linux": "linux",
    "Windows": "windows",
}


def parse_build_identity(raw: bytes) -> dict[str, Any]:
    """Extract the compiled target and optimize mode from a product registry."""
    if len(raw) > MAX_CAPTURE_BYTES:
        raise BenchmarkError("prover registry output is oversized")
    try:
        root = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError("prover registry is not valid JSON") from error
    product = root.get("product") if isinstance(root, dict) else None
    target = product.get("target") if isinstance(product, dict) else None
    if not isinstance(product, dict) or not isinstance(target, dict):
        raise BenchmarkError(
            "prover registry publishes no build identity; benchmark only a "
            "focused product CLI whose `applications` reports product.target "
            "and product.optimize"
        )
    identity = {
        "arch": target.get("arch"),
        "os": target.get("os"),
        "abi": target.get("abi"),
        "cpu_model": target.get("cpu_model"),
        "optimize": product.get("optimize"),
    }
    absent = [
        name
        for name in IDENTITY_FIELDS
        if not isinstance(identity[name], str) or not identity[name]
    ]
    if absent:
        raise BenchmarkError(f"prover build identity is incomplete: {absent}")
    return identity


def validate_build_identity(
    identity: Mapping[str, Any],
    *,
    machine: str | None = None,
    system: str | None = None,
) -> None:
    """Refuse a binary this host cannot run, or one not built for publication."""
    machine = platform.machine() if machine is None else machine
    system = platform.system() if system is None else system
    expected_arch = HOST_ARCHITECTURES.get(machine)
    expected_os = HOST_OPERATING_SYSTEMS.get(system)
    if expected_arch is None or expected_os is None:
        raise BenchmarkError(
            f"cannot map host {system}/{machine} onto a build target; "
            "refusing to benchmark an unverifiable executable"
        )
    if identity["arch"] != expected_arch or identity["os"] != expected_os:
        raise BenchmarkError(
            f"prover executable targets {identity['arch']}-{identity['os']} "
            f"but this host is {expected_arch}-{expected_os}; a translated or "
            "foreign build cannot produce comparable timings"
        )
    if identity["optimize"] != PUBLICATION_OPTIMIZE:
        raise BenchmarkError(
            f"prover executable was built at {identity['optimize']}; CSP "
            f"timings require -Doptimize={PUBLICATION_OPTIMIZE}"
        )


def read_build_identity(cli: Path, *, timeout: int = 30) -> dict[str, Any]:
    """Read the build identity the executable about to be benchmarked publishes."""
    try:
        completed = subprocess.run(
            [str(cli), "applications"],
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except OSError as error:
        raise BenchmarkError(
            f"cannot execute {cli}: {error}; a binary built for another "
            "architecture cannot be benchmarked on this host"
        ) from error
    except subprocess.SubprocessError as error:
        raise BenchmarkError(
            f"cannot read the build identity of {cli}: {error}"
        ) from error
    if completed.returncode != 0:
        raise BenchmarkError(
            f"build identity registry of {cli} exited {completed.returncode}"
        )
    return parse_build_identity(completed.stdout)
