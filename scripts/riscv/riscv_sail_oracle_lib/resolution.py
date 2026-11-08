"""Resolve and identity-verify the pinned Sail executable."""

from __future__ import annotations

import dataclasses
import os
import subprocess
from pathlib import Path
from typing import Mapping

try:
    from riscv_equivalence_lib import contract, sail_identity
except ModuleNotFoundError:  # Imported as scripts.riscv_sail_oracle_lib.
    from scripts.riscv_equivalence_lib import contract, sail_identity

ENV_SAIL_BIN = "STWO_RISCV_SAIL_BIN"
ENV_WORKSPACE = "STWO_RISCV_FORMAL_WORKSPACE"
DEFAULT_WORKSPACE = Path("/tmp/stwo-riscv-formal")
SAIL_BINARY_IN_WORKSPACE = Path("source/sail-riscv/build/c_emulator/sail_riscv_sim")


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
    """Find and identity-verify the first configured Sail binary."""
    candidate, source = first_configured_candidate(explicit, environ)
    if not candidate.is_file():
        raise SailUnavailable(
            f"pinned Sail binary not found at {candidate} (from {source}); "
            f"build it with: python3 scripts/riscv_formal_tools.py prepare "
            f"--workspace {DEFAULT_WORKSPACE}"
        )
    try:
        identity = sail_identity.verify_sail_binary(candidate)
    except (
        contract.EquivalenceError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        raise SailUnavailable(
            f"{candidate} (from {source}) is not the pinned Sail oracle: {error}"
        ) from error
    return ResolvedSail(binary=candidate, identity=identity, source=source)


def first_configured_candidate(
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
