"""Typed parser for the repository's upstream authority ledger."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = ROOT / "conformance" / "upstream.md"
REVISION_RE = r"[0-9a-f]{40}"


class PinLedgerError(ValueError):
    """The checked-in upstream ledger is missing or ambiguous."""


@dataclasses.dataclass(frozen=True)
class PinLedger:
    native_repository: str
    native_revision: str
    riscv_sail_repository: str
    riscv_sail_revision: str
    riscv_sail_compiler_version: str
    riscv_spike_repository: str
    riscv_spike_revision: str
    riscv_arch_test_repository: str
    riscv_arch_test_revision: str
    riscv_legacy_repository: str
    riscv_legacy_revision: str
    official_cairo_repository: str
    official_cairo_revision: str
    official_cairo_stwo_repository: str
    official_cairo_stwo_revision: str
    cairo_language_repository: str
    cairo_language_revision: str
    cairo_language_version: str
    cairo_vm_version: str
    cairo_repository: str
    cairo_revision: str
    cairo_stwo_repository: str
    cairo_stwo_revision: str
    cairo_prover_stwo_revision: str


def _single_field(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise PinLedgerError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def parse_ledger(path: Path = DEFAULT_LEDGER) -> PinLedger:
    text = path.read_text(encoding="utf-8")
    return PinLedger(
        native_repository=_single_field(
            text, r"^- Upstream repository: `([^`]+)`$", "Native Stwo repository"
        ),
        native_revision=_single_field(
            text, rf"^- Pinned commit: `({REVISION_RE})`$", "Native Stwo revision"
        ),
        riscv_sail_repository=_single_field(
            text, r"^- Sail RISC-V repository: `([^`]+)`$", "Sail RISC-V repository"
        ),
        riscv_sail_revision=_single_field(
            text,
            rf"^- Pinned Sail RISC-V commit: `({REVISION_RE})`$",
            "Sail RISC-V revision",
        ),
        riscv_sail_compiler_version=_single_field(
            text,
            r"^- Pinned Sail compiler version: `([^`]+)`$",
            "Sail compiler version",
        ),
        riscv_spike_repository=_single_field(
            text, r"^- Spike repository: `([^`]+)`$", "Spike repository"
        ),
        riscv_spike_revision=_single_field(
            text,
            rf"^- Pinned Spike commit: `({REVISION_RE})`$",
            "Spike revision",
        ),
        riscv_arch_test_repository=_single_field(
            text,
            r"^- RISC-V Architectural Tests repository: `([^`]+)`$",
            "RISC-V Architectural Tests repository",
        ),
        riscv_arch_test_revision=_single_field(
            text,
            rf"^- Pinned RISC-V Architectural Tests commit: `({REVISION_RE})`$",
            "RISC-V Architectural Tests revision",
        ),
        riscv_legacy_repository=_single_field(
            text,
            r"^- Legacy Stark-V repository: `([^`]+)`$",
            "legacy Stark-V repository",
        ),
        riscv_legacy_revision=_single_field(
            text,
            rf"^- Pinned legacy Stark-V commit: `({REVISION_RE})`$",
            "legacy Stark-V revision",
        ),
        official_cairo_repository=_single_field(
            text,
            r"^- Official Stwo-Cairo repository: `([^`]+)`$",
            "official Stwo-Cairo repository",
        ),
        official_cairo_revision=_single_field(
            text,
            rf"^- Pinned official Stwo-Cairo commit: `({REVISION_RE})`$",
            "official Stwo-Cairo revision",
        ),
        official_cairo_stwo_repository=_single_field(
            text,
            r"^- Official Cairo Stwo repository: `([^`]+)`$",
            "official Cairo Stwo repository",
        ),
        official_cairo_stwo_revision=_single_field(
            text,
            rf"^- Pinned official Cairo Stwo commit: `({REVISION_RE})`$",
            "official Cairo Stwo revision",
        ),
        cairo_language_repository=_single_field(
            text,
            r"^- Cairo language repository: `([^`]+)`$",
            "Cairo language repository",
        ),
        cairo_language_revision=_single_field(
            text,
            rf"^- Pinned Cairo language commit: `({REVISION_RE})`$",
            "Cairo language revision",
        ),
        cairo_language_version=_single_field(
            text,
            r"^- Cairo language version: `([0-9]+\.[0-9]+\.[0-9]+)`$",
            "Cairo language version",
        ),
        cairo_vm_version=_single_field(
            text,
            r"^- Cairo VM version: `([0-9]+\.[0-9]+\.[0-9]+)`$",
            "Cairo VM version",
        ),
        cairo_repository=_single_field(
            text, r"^- Stwo-Cairo repository: `([^`]+)`$", "Cairo Stwo-Cairo repository"
        ),
        cairo_revision=_single_field(
            text,
            rf"^- Pinned Stwo-Cairo commit: `({REVISION_RE})`$",
            "Cairo Stwo-Cairo revision",
        ),
        cairo_stwo_repository=_single_field(
            text, r"^- Stwo repository: `([^`]+)`$", "Cairo Stwo repository"
        ),
        cairo_stwo_revision=_single_field(
            text,
            rf"^- Pinned Cairo verifier Stwo commit: `({REVISION_RE})`$",
            "Cairo verifier Stwo revision",
        ),
        cairo_prover_stwo_revision=_single_field(
            text,
            rf"^- Pinned Cairo prover Stwo commit: `({REVISION_RE})`$",
            "Cairo prover Stwo revision",
        ),
    )
