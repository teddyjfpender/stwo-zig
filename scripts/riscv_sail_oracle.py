#!/usr/bin/env python3
"""One reusable verdict interface over the pinned Sail oracle.

Answers exactly one question: does the pinned Sail model agree with a
runner retirement trace? Callers receive one of four verdicts:

  EQUIVALENT   Sail retired the same sequence on every compared field
               (pc, instruction, rd, rd_value, next_pc, and the five
               memory-effect fields).
  DIVERGENT    Sail was consulted and contradicts the trace. Fail loudly.
  UNAVAILABLE  The pinned Sail binary cannot be consulted on this host.
               Skip VISIBLY, naming what was not checked.
  ERROR        The inputs or the RVFI-DII transport are broken. Fail
               loudly; skipping here lets a harness bug read as coverage.

UNAVAILABLE is decided strictly before the oracle is consulted: the
binary is missing, or exists but fails the pinned identity check
(model tag, Sail compiler version, transport-patch hash). Once a
verified binary starts answering, nothing downgrades to UNAVAILABLE --
conflating "the oracle is absent" with "the oracle disagrees" is how a
dead oracle starts to look like a passing one.

Exit codes mirror verdicts: 0 EQUIVALENT, 1 DIVERGENT, 2 ERROR,
3 UNAVAILABLE. stdout is a single JSON report; humans and Zig tests
parse the same object. Comparison semantics live in
scripts/riscv_equivalence.py; this module adds only resolution,
classification, and the report shape.

  python3 scripts/riscv_sail_oracle.py probe
  python3 scripts/riscv_sail_oracle.py check --elf guest.elf --trace trace.json

The binary is resolved from, in order: --sail-bin, $STWO_RISCV_SAIL_BIN,
$STWO_RISCV_FORMAL_WORKSPACE, then the documented default workspace
/tmp/stwo-riscv-formal (scripts/riscv_formal_tools.py prepare). The
first candidate that is configured wins and must verify; a configured
but wrong binary is never silently papered over by a later candidate.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

if __package__:
    from scripts import riscv_equivalence as equivalence
else:  # direct execution: python3 scripts/riscv_sail_oracle.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import riscv_equivalence as equivalence


REPORT_SCHEMA = "stwo-riscv-sail-oracle-report-v1"

VERDICT_EQUIVALENT = "EQUIVALENT"
VERDICT_DIVERGENT = "DIVERGENT"
VERDICT_ERROR = "ERROR"
VERDICT_UNAVAILABLE = "UNAVAILABLE"
VERDICT_AVAILABLE = "AVAILABLE"  # probe-only: present and pinned, not consulted

# A caller must be able to skip on absence and fail on everything else by
# exit code alone, without parsing the report.
EXIT_CODES = {
    VERDICT_EQUIVALENT: 0,
    VERDICT_AVAILABLE: 0,
    VERDICT_DIVERGENT: 1,
    VERDICT_ERROR: 2,
    VERDICT_UNAVAILABLE: 3,
}

ENV_SAIL_BIN = "STWO_RISCV_SAIL_BIN"
ENV_WORKSPACE = "STWO_RISCV_FORMAL_WORKSPACE"
DEFAULT_WORKSPACE = Path("/tmp/stwo-riscv-formal")
SAIL_BINARY_IN_WORKSPACE = Path("source/sail-riscv/build/c_emulator/sail_riscv_sim")

COMPARED_FIELDS = (
    "pc",
    "instruction",
    "rd",
    "rd_value",
    "next_pc",
    "memory.address",
    "memory.read_mask",
    "memory.read_value",
    "memory.write_mask",
    "memory.write_value",
)


class SailUnavailable(RuntimeError):
    """The pinned Sail oracle cannot be consulted on this host."""


@dataclasses.dataclass(frozen=True)
class ResolvedSail:
    """A Sail binary that has already passed the pinned identity check."""

    binary: Path
    identity: dict[str, str]
    source: str


def resolve_sail(
    explicit: Path | None = None,
    environ: Mapping[str, str] = os.environ,
) -> ResolvedSail:
    """Find and identity-verify the pinned Sail binary, or raise SailUnavailable.

    The first *configured* candidate is authoritative: if --sail-bin or an
    environment variable names a binary that is missing or fails the pin,
    that is UNAVAILABLE with the precise reason, not a fall-through to some
    other binary that happens to exist. Falling through would let a
    misconfigured caller believe it checked the binary it named.
    """
    candidate, source = _first_configured_candidate(explicit, environ)
    if not candidate.is_file():
        raise SailUnavailable(
            f"pinned Sail binary not found at {candidate} (from {source}); "
            f"build it with: python3 scripts/riscv_formal_tools.py prepare "
            f"--workspace {DEFAULT_WORKSPACE}"
        )
    try:
        identity = equivalence.verify_sail_binary(candidate)
    except (
        equivalence.EquivalenceError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        raise SailUnavailable(
            f"{candidate} (from {source}) is not the pinned Sail oracle: {error}"
        ) from error
    return ResolvedSail(binary=candidate, identity=identity, source=source)


def _first_configured_candidate(
    explicit: Path | None,
    environ: Mapping[str, str],
) -> tuple[Path, str]:
    if explicit is not None:
        return Path(explicit), "--sail-bin"
    env_bin = environ.get(ENV_SAIL_BIN)
    if env_bin:
        return Path(env_bin), f"${ENV_SAIL_BIN}"
    env_workspace = environ.get(ENV_WORKSPACE)
    if env_workspace:
        return (
            Path(env_workspace) / SAIL_BINARY_IN_WORKSPACE,
            f"${ENV_WORKSPACE}",
        )
    return (
        DEFAULT_WORKSPACE / SAIL_BINARY_IN_WORKSPACE,
        f"default workspace {DEFAULT_WORKSPACE}",
    )


def probe(
    explicit: Path | None = None,
    environ: Mapping[str, str] = os.environ,
) -> dict[str, Any]:
    """Report whether the pinned oracle is consultable, without consulting it."""
    started = time.monotonic()
    try:
        resolved = resolve_sail(explicit, environ)
    except SailUnavailable as error:
        return _report(VERDICT_UNAVAILABLE, str(error), started)
    return _report(
        VERDICT_AVAILABLE,
        "",
        started,
        identity=resolved.identity,
        sail_source=resolved.source,
    )


def check_trace_agreement(
    elf_path: Path,
    trace_path: Path,
    sail_bin: Path | None = None,
    environ: Mapping[str, str] = os.environ,
) -> dict[str, Any]:
    """Replay a runner trace through pinned Sail and classify the outcome.

    The ELF is recorded by hash so the report names which guest was checked;
    Sail itself replays the retired instruction words from the trace over
    RVFI-DII, so agreement is judged on the trace's own claims.
    """
    started = time.monotonic()
    try:
        resolved = resolve_sail(sail_bin, environ)
    except SailUnavailable as error:
        return _report(VERDICT_UNAVAILABLE, str(error), started)

    # From here on the oracle is present and pinned: every failure must be
    # loud (DIVERGENT or ERROR), never a skip.
    try:
        elf_sha256 = _sha256_file(Path(elf_path))
        zig_trace = equivalence.load_trace(trace_path)
    except (equivalence.EquivalenceError, OSError) as error:
        return _report(VERDICT_ERROR, f"input artefact rejected: {error}", started)

    common = {
        "identity": resolved.identity,
        "sail_source": resolved.source,
        "elf_sha256": elf_sha256,
        "retirements": zig_trace["total_steps"],
    }
    try:
        sail_trace = equivalence.run_sail_rvfi_dii(resolved.binary, zig_trace)
    except equivalence.SailDisagreement as error:
        return _report(VERDICT_DIVERGENT, str(error), started, **common)
    except (
        equivalence.EquivalenceError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        return _report(
            VERDICT_ERROR, f"Sail RVFI-DII session failed: {error}", started, **common
        )

    differences = equivalence.compare_traces(sail_trace, zig_trace)
    if differences:
        return _report(
            VERDICT_DIVERGENT,
            f"{len(differences)} retirement field difference(s)",
            started,
            differences=differences,
            **common,
        )
    return _report(VERDICT_EQUIVALENT, "", started, **common)


def _report(
    verdict: str,
    reason: str,
    started: float,
    *,
    differences: list[str] | None = None,
    identity: dict[str, str] | None = None,
    sail_source: str = "",
    elf_sha256: str = "",
    retirements: int = 0,
) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "verdict": verdict,
        "exit_code": EXIT_CODES[verdict],
        "reason": reason,
        "differences": differences or [],
        "compared_fields": list(COMPARED_FIELDS),
        "identity": identity or {},
        "sail_source": sail_source,
        "elf_sha256": elf_sha256,
        "retirements": retirements,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    probe_cmd = sub.add_parser("probe", help="report oracle availability only")
    probe_cmd.add_argument("--sail-bin", type=Path)
    check_cmd = sub.add_parser("check", help="replay one trace through pinned Sail")
    check_cmd.add_argument("--elf", type=Path, required=True)
    check_cmd.add_argument("--trace", type=Path, required=True)
    check_cmd.add_argument("--sail-bin", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "probe":
        report = probe(args.sail_bin)
    else:
        report = check_trace_agreement(args.elf, args.trace, args.sail_bin)
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
