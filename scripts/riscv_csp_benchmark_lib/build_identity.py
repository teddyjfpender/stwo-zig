"""Fail-closed provenance validation of the executables a run measures with.

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

The trace dumper produces every published cycle count and all negative-case
evidence, so it is validated here too -- but it publishes a *different*
surface.  It has no ``applications`` registry at all (``riscv-trace-dump
applications`` exits nonzero with ``UnknownOption``), so its target and
optimize mode are genuinely unavailable and this module says so explicitly
rather than implying a check it cannot perform.  What it does publish, in
every ``--public-values`` dump, is a provenance block binding the executable to
an implementation commit, a dirty flag, and the digest of the ELF it just ran;
that is validated against the repository HEAD before any measurement starts.
"""

from __future__ import annotations

import json
import platform
import subprocess
from pathlib import Path
from typing import Any, Mapping

from scripts.riscv_csp_benchmark_lib.contract import (
    BenchmarkError,
    Case,
    HEX_32,
    HEX_40,
    MAX_CAPTURE_BYTES,
    _strict_object,
)
from scripts.riscv_csp_benchmark_lib.host import host_architecture


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
TRACE_SCHEMA = "riscv-public-values-diagnostic-v1"
TRACE_DERIVATION = "execution_and_committed_tree_builders_without_proof_admission"
TRACE_PROVENANCE_FIELDS = (
    "implementation_commit",
    "implementation_dirty",
    "oracle_commit",
    "witness_layout_sha256",
)
# Named so the report states what the trace dumper cannot be held to, instead
# of leaving a reader to assume it received the prover's identity checks.
TRACE_UNVALIDATED = (
    "target architecture, operating system, ABI, and CPU model",
    "optimize mode",
)


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
    host_arch: str | None = None,
    system: str | None = None,
) -> None:
    """Refuse a binary this host cannot run, or one not built for publication.

    The comparison is against the *hardware* architecture from
    ``host.host_architecture``, never ``platform.machine()``: under a
    translated interpreter the latter reports x86_64 on an arm64 Mac and would
    admit exactly the Rosetta build this check exists to catch.  A host that
    cannot be established at all is refused.
    """
    host_arch = host_architecture() if host_arch is None else host_arch
    system = platform.system() if system is None else system
    expected_arch = None if host_arch is None else HOST_ARCHITECTURES.get(host_arch)
    expected_os = HOST_OPERATING_SYSTEMS.get(system)
    if expected_arch is None or expected_os is None:
        raise BenchmarkError(
            f"cannot map host {system}/{host_arch or 'undetermined architecture'} "
            "onto a build target; refusing to benchmark an unverifiable executable"
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


def parse_trace_provenance(
    raw: bytes,
    *,
    guest_sha256: str,
    input_sha256: str,
) -> dict[str, Any]:
    """Extract the trace dumper's published provenance from a diagnostic dump.

    The dump's ``source`` digests are checked against the authenticated fixture
    the probe asked for, so the provenance cannot be a stale or substituted
    document produced from some other program.
    """
    if len(raw) > MAX_CAPTURE_BYTES:
        raise BenchmarkError("trace diagnostic output is oversized")
    try:
        root = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError("trace diagnostic is not valid JSON") from error
    if not isinstance(root, dict) or root.get("schema") != TRACE_SCHEMA:
        raise BenchmarkError("trace diagnostic schema drifted")
    if root.get("derivation") != TRACE_DERIVATION:
        raise BenchmarkError("trace diagnostic derivation drifted")
    source = root.get("source")
    if (
        not isinstance(source, dict)
        or source.get("elf_sha256") != guest_sha256
        or source.get("input_sha256") != input_sha256
    ):
        raise BenchmarkError(
            "trace diagnostic is not bound to the authenticated fixture it was "
            "asked for; its provenance describes another program"
        )
    published = root.get("provenance")
    if not isinstance(published, dict):
        raise BenchmarkError("trace executable publishes no provenance block")
    provenance = {name: published.get(name) for name in TRACE_PROVENANCE_FIELDS}
    if (
        not isinstance(provenance["implementation_commit"], str)
        or HEX_40.match(provenance["implementation_commit"]) is None
        or not isinstance(provenance["implementation_dirty"], bool)
        or not isinstance(provenance["oracle_commit"], str)
        or not provenance["oracle_commit"]
        or not isinstance(provenance["witness_layout_sha256"], str)
        or HEX_32.match(provenance["witness_layout_sha256"]) is None
    ):
        raise BenchmarkError("trace executable provenance is incomplete")
    return provenance


def validate_trace_provenance(
    provenance: Mapping[str, Any],
    *,
    repository_head: str,
) -> None:
    """Hold the trace dumper to the same commit gate the prover CLI gets."""
    if provenance["implementation_dirty"]:
        raise BenchmarkError(
            "trace executable was built from a dirty worktree; its cycle "
            "counts and negative-case evidence are not reproducible"
        )
    if provenance["implementation_commit"] != repository_head:
        raise BenchmarkError(
            f"trace executable was built at commit "
            f"{provenance['implementation_commit']} but the repository HEAD is "
            f"{repository_head}; rebuild it before measuring"
        )


def read_trace_provenance(
    trace_cli: Path,
    case: Case,
    *,
    repository_head: str,
    max_steps: int,
    timeout: int,
) -> dict[str, Any]:
    """Validate the trace executable before it produces any published number.

    Runs one authenticated fixture through the same ``--public-values`` mode
    the benchmark uses, so the provenance validated here is the provenance of
    the exact code path that will report cycles.
    """
    command = [
        str(trace_cli),
        "--public-values",
        str(case.guest_path),
        "--input",
        str(case.input_path),
        "--max-steps",
        str(max_steps),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except OSError as error:
        raise BenchmarkError(
            f"cannot execute {trace_cli}: {error}; a binary built for another "
            "architecture cannot produce this host's cycle counts"
        ) from error
    except subprocess.SubprocessError as error:
        raise BenchmarkError(
            f"cannot read the provenance of {trace_cli}: {error}"
        ) from error
    if completed.returncode != 0:
        raise BenchmarkError(
            f"trace provenance probe of {trace_cli} exited {completed.returncode}"
        )
    provenance = parse_trace_provenance(
        completed.stdout,
        guest_sha256=case.guest_sha256,
        input_sha256=case.input_sha256,
    )
    validate_trace_provenance(provenance, repository_head=repository_head)
    return {
        **provenance,
        "surface": "public-values diagnostic provenance",
        "build_identity_published": False,
        "unvalidated": list(TRACE_UNVALIDATED),
        "unvalidated_reason": (
            "the trace dumper publishes no `applications` registry, so the "
            "target and optimize checks the prover CLI receives have no "
            "source here; it contributes cycle counts, not timings"
        ),
    }
