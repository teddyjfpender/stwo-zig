"""Validate the SM83 authority carriers against the upstream ledger."""

from __future__ import annotations

import re
from pathlib import Path

from .model import PinLedger, REVISION_RE


def check(root: Path, ledger: PinLedger) -> list[str]:
    authority = "src/frontends/sm83/isa/authority.zig"
    gate = "scripts/sm83_frontend_gate.py"
    specs = (
        (authority, "SM83 opcode repository", r'^pub const opcode_repository = "([^"]+)";$', ledger.sm83_opcode_repository),
        (authority, "SM83 opcode revision", rf'^pub const opcode_revision = "({REVISION_RE})";$', ledger.sm83_opcode_revision),
        (authority, "SM83 opcode JSON SHA-256", r'^pub const opcode_json_sha256 = "([0-9a-f]{64})";$', ledger.sm83_opcode_json_sha256),
        (authority, "Pan Docs repository", r'^pub const pandocs_repository = "([^"]+)";$', ledger.sm83_pandocs_repository),
        (authority, "Pan Docs revision", rf'^pub const pandocs_revision = "({REVISION_RE})";$', ledger.sm83_pandocs_revision),
        (authority, "SM83 SingleStepTests repository", r'^pub const single_step_repository = "([^"]+)";$', ledger.sm83_single_step_repository),
        (authority, "SM83 SingleStepTests revision", rf'^pub const single_step_revision = "({REVISION_RE})";$', ledger.sm83_single_step_revision),
        (authority, "SM83 SingleStepTests v1 SHA-256", r'^pub const single_step_v1_sha256 = "([0-9a-f]{64})";$', ledger.sm83_single_step_v1_sha256),
        (gate, "SM83 corpus repository", r'^CORPUS_REPOSITORY = "([^"]+)"$', ledger.sm83_single_step_repository),
        (gate, "SM83 corpus revision", rf'^CORPUS_REVISION = "({REVISION_RE})"$', ledger.sm83_single_step_revision),
        (gate, "Blargg gate repository", r'^BLARGG_REPOSITORY = "([^"]+)"$', ledger.sm83_blargg_repository),
        (gate, "Blargg gate revision", rf'^BLARGG_REVISION = "({REVISION_RE})"$', ledger.sm83_blargg_revision),
        (authority, "SameBoy repository", r'^pub const sameboy_repository = "([^"]+)";$', ledger.sm83_sameboy_repository),
        (authority, "SameBoy revision", rf'^pub const sameboy_revision = "({REVISION_RE})";$', ledger.sm83_sameboy_revision),
        (authority, "Blargg repository", r'^pub const blargg_repository = "([^"]+)";$', ledger.sm83_blargg_repository),
        (authority, "Blargg revision", rf'^pub const blargg_revision = "({REVISION_RE})";$', ledger.sm83_blargg_revision),
        (authority, "Mooneye repository", r'^pub const mooneye_repository = "([^"]+)";$', ledger.sm83_mooneye_repository),
        (authority, "Mooneye revision", rf'^pub const mooneye_revision = "({REVISION_RE})";$', ledger.sm83_mooneye_revision),
        (authority, "Mooneye WLA-DX revision", rf'^pub const mooneye_wla_revision = "({REVISION_RE})";$', ledger.sm83_mooneye_wla_revision),
        (authority, "Mooneye release", r'^pub const mooneye_release = "([^"]+)";$', ledger.sm83_mooneye_release),
        (authority, "Mooneye release SHA-256", r'^pub const mooneye_release_sha256 = "([0-9a-f]{64})";$', ledger.sm83_mooneye_release_sha256),
        (gate, "Mooneye gate release", r'^MOONEYE_RELEASE = "([^"]+)"$', ledger.sm83_mooneye_release),
        (gate, "Mooneye gate release SHA-256", r'^MOONEYE_RELEASE_SHA256 = "([0-9a-f]{64})"$', ledger.sm83_mooneye_release_sha256),
    )
    errors: list[str] = []
    sources: dict[str, str] = {}
    for path, label, pattern, expected in specs:
        try:
            if path not in sources:
                sources[path] = (root / path).read_text(encoding="utf-8")
            text = sources[path]
        except OSError as error:
            errors.append(f"{path}: unable to read {label}: {error}")
            continue
        matches = re.findall(pattern, text, flags=re.MULTILINE)
        if len(matches) != 1:
            errors.append(f"{path}: expected exactly one {label}, found {len(matches)}")
        elif matches[0] != expected:
            errors.append(f"{path}: {label} is {matches[0]!r}, expected {expected!r}")
    return errors
