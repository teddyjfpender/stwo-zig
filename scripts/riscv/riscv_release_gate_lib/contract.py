"""Active source and release contracts for the Sail-backed RISC-V frontend."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ZIG_IMPORT_RE = re.compile(r'@import\("([^"\n]+)"\)')
ZIG_NON_CODE_RE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', re.DOTALL)
ACTIVE_PLACEHOLDER_RE = re.compile(r"\b(?:legacy|placeholder|silent)\b")
MANUAL_SOURCE_CEILING = 850
AIR_SOUNDNESS_LEDGER_ROW = ("RISC-V", "Opcode AIR constraint and lookup layout")
ALLOWED_ACTIVE_DIVERGENCES = frozenset({
    ("RISC-V", "PCS geometry"),
    ("RISC-V", "Interaction transcript"),
    ("RISC-V", "RV32IM decode boundary"),
    AIR_SOUNDNESS_LEDGER_ROW,
})
# Rows whose absence is itself a failure. In particular, the AIR-soundness row
# records the proof boundary that remains outside the executable Sail oracle.
REQUIRED_ARCHITECTURAL_DIVERGENCES = frozenset({
    ("RISC-V", "PCS geometry"),
    ("RISC-V", "Interaction transcript"),
    AIR_SOUNDNESS_LEDGER_ROW,
})


def _contains_assignment(source: str, name: str, value: str) -> bool:
    pattern = rf'pub\s+const\s+{re.escape(name)}\s*=\s*"{re.escape(value)}"\s*;'
    return re.search(pattern, source) is not None


def _contains_bool_assignment(source: str, name: str, value: bool) -> bool:
    rendered = "true" if value else "false"
    pattern = rf"pub\s+const\s+{re.escape(name)}\s*=\s*{rendered}\s*;"
    return re.search(pattern, source) is not None


def _riscv_capability_alias(registry_source: str) -> str | None:
    match = re.search(
        r'const\s+([A-Za-z_]\w*)\s*=\s*@import\("riscv_cpu_capabilities"\)\s*;',
        registry_source,
    )
    return match.group(1) if match is not None else None


def _contains_member_assignment(source: str, name: str, owner: str, member: str) -> bool:
    pattern = (
        rf"pub\s+const\s+{re.escape(name)}\s*=\s*"
        rf"{re.escape(owner)}\s*\.\s*{re.escape(member)}\s*;"
    )
    return re.search(pattern, source) is not None


def _conditional_print_body(source: str, condition: str) -> str | None:
    pattern = (
        rf"if\s*\(\s*{condition}\s*\)\s*try\s+writer\.print\s*\("
        r"(?P<body>.*?)\)\s*;"
    )
    match = re.search(pattern, source, re.DOTALL)
    return match.group("body") if match is not None else None


def _registry_wiring_errors(registry_source: str) -> list[str]:
    alias = _riscv_capability_alias(registry_source)
    if alias is None:
        return ["registry does not import the typed RISC-V CPU capabilities"]

    errors: list[str] = []
    if not _contains_member_assignment(
            registry_source, "RISCV_ADAPTER_RELEASE_GATED", alias, "adapter_release_gated"):
        errors.append("registry admission switch does not alias the RISC-V capability owner")

    admission_pattern = (
        r"pub\s+fn\s+requireRiscVAdmission\s*\(\s*experimental\s*:\s*bool\s*\)\s*"
        rf"!void\s*\{{\s*return\s+{re.escape(alias)}\.requireAdmission\s*\(\s*"
        r"experimental\s*\)\s*;\s*\}"
    )
    if re.search(admission_pattern, registry_source, re.DOTALL) is None:
        errors.append("registry does not delegate RISC-V admission to the capability owner")

    release_body = _conditional_print_body(
        registry_source, re.escape("RISCV_ADAPTER_RELEASE_GATED")
    )
    deferred_body = _conditional_print_body(
        registry_source, rf"!\s*{re.escape('RISCV_ADAPTER_RELEASE_GATED')}"
    )
    release_members = ("adapter", "air", "isa", "backend")
    deferred_members = ("adapter", "isa", "backend", "deferred_reason")
    if release_body is None or any(
            re.search(rf"\b{re.escape(alias)}\s*\.\s*{member}\b", release_body) is None
            for member in release_members
    ) or '"status":"release_gated"' not in release_body:
        errors.append("registry release branch is not wired to the typed RISC-V capability")
    if deferred_body is None or any(
            re.search(rf"\b{re.escape(alias)}\s*\.\s*{member}\b", deferred_body) is None
            for member in deferred_members
    ) or '"status":"not_release_gated"' not in deferred_body:
        errors.append("registry deferred branch is not wired to the typed RISC-V capability")
    return errors


def phase_errors(
    phase: str,
    registry_source: str,
    capability_source: str,
    artifact_source: str,
    cli_source: str,
) -> list[str]:
    """Return every source-level release-state mismatch for ``phase``."""
    if phase not in {"candidate", "promoted"}:
        return [f"unknown release phase: {phase}"]
    errors: list[str] = []
    expected = "not_release_gated" if phase == "candidate" else "release_gated"
    if not _contains_assignment(artifact_source, "RELEASE_STATUS", expected):
        errors.append(f"artifact RELEASE_STATUS is not {expected}")

    promoted = phase == "promoted"
    if not _contains_bool_assignment(capability_source, "adapter_release_gated", promoted):
        errors.append(f"RISC-V capability owner does not select the {phase} phase")
    for name, value in (
        ("adapter", "sail-rv32im-zkvm-elf"),
        ("air", "sail_rv32im_zkvm_v1"),
        ("isa", "rv32im"),
        ("backend", "cpu"),
    ):
        if not _contains_assignment(capability_source, name, value):
            errors.append(f"RISC-V capability {name} is not {value}")
    reason = re.search(
        r'pub\s+const\s+deferred_reason\s*=\s*"((?:\\.|[^"\\])*)"\s*;',
        capability_source,
    )
    if reason is None or not reason.group(1).strip():
        errors.append("RISC-V capability owner lacks a non-empty deferred reason")
    errors.extend(_registry_wiring_errors(registry_source))
    if "Flag.experimental" not in cli_source or '"--experimental"' not in cli_source:
        errors.append("CLI lacks the typed --experimental admission flag")
    return errors


def divergence_ledger_errors(text: str) -> list[str]:
    """Reject active divergences except narrow, explicitly documented exceptions."""
    marker = "## Active divergences"
    if marker not in text:
        return ["divergence ledger has no Active divergences section"]
    active = text.split(marker, 1)[1].split("\n## ", 1)[0]
    rows: dict[tuple[str, str], str] = {}
    errors: list[str] = []
    for raw_line in active.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or cells[0] == "Lane" or all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        if len(cells) != 5:
            errors.append("divergence ledger contains a malformed active table row")
            continue
        key = (cells[0], cells[1])
        if key in rows:
            errors.append(f"divergence ledger contains duplicate active row: {key[0]} / {key[1]}")
            continue
        rows[key] = cells[4]

    if not rows:
        errors.append("divergence ledger active table is empty or malformed")
    for key, status in sorted(rows.items()):
        if key in ALLOWED_ACTIVE_DIVERGENCES:
            if not status.startswith("Allowed only with "):
                errors.append(
                    f"allowlisted divergence lacks its conditional status: {key[0]} / {key[1]}"
                )
            continue
        errors.append(f"release-blocking divergence remains active: {key[0]} / {key[1]}")

    for key in REQUIRED_ARCHITECTURAL_DIVERGENCES:
        if key not in rows:
            errors.append(
                "required architectural divergence is missing: "
                f"{key[0]} / {key[1]}"
            )

    return errors


def divergence_errors(root: Path) -> list[str]:
    ledger = root / "conformance/divergence-log.md"
    if not ledger.is_file():
        return ["missing required release artifact: conformance/divergence-log.md"]
    return divergence_ledger_errors(ledger.read_text(encoding="utf-8"))


def repository_contract_errors(root: Path, phase: str) -> list[str]:
    required = (
        "conformance/2026-07-26-riscv-sail-contract.md",
        "conformance/divergence-log.md",
        "scripts/riscv_release_gate.py",
        "scripts/riscv_formal_tools.py",
        "scripts/riscv_arch_tests.py",
        "scripts/riscv_staged_smoke.py",
        "scripts/riscv_trace_vectors.py",
        "src/frontends/riscv/air/lang/typed_mulh_authority.zig",
        "src/products/riscv_cpu/capabilities.zig",
    )
    errors = [f"missing required release artifact: {path}" for path in required if not (root / path).is_file()]
    registry = (root / "src/tools/prove/registry.zig").read_text(encoding="utf-8")
    capability = (root / "src/products/riscv_cpu/capabilities.zig").read_text(encoding="utf-8")
    artifact = (root / "src/interop/riscv_artifact.zig").read_text(encoding="utf-8")
    cli = (root / "src/tools/prove/cli.zig").read_text(encoding="utf-8")
    errors.extend(phase_errors(phase, registry, capability, artifact, cli))
    errors.extend(divergence_errors(root))
    return errors


def _zig_sources(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.rglob("*.zig")
        if path.is_file()
        and not {".zig-cache", "generated", "vendor", "zig-out"}.intersection(path.parts)
    )


def _resolved_src_import(source: Path, imported: str, src_root: Path) -> Path | None:
    if not imported.startswith(".") or not imported.endswith(".zig"):
        return None
    target = (source.parent / imported).resolve()
    try:
        relative = target.relative_to(src_root.resolve())
    except ValueError:
        return None
    return relative if target.is_file() else None


def _generated_zig(source: str) -> bool:
    header = "\n".join(source.splitlines()[:8]).lower()
    return "generated" in header and "generator:" in header and "regenerate:" in header


def core_purity_errors(root: Path) -> list[str]:
    """Reject core dependencies on a frontend or concrete backend owner."""
    src_root = root / "src"
    errors: list[str] = []
    forbidden = {"backends", "frontends", "integrations"}
    for source in _zig_sources(src_root / "core"):
        text = source.read_text(encoding="utf-8")
        for imported in ZIG_IMPORT_RE.findall(text):
            target = _resolved_src_import(source, imported, src_root)
            if target is not None and target.parts and target.parts[0] in forbidden:
                display = source.relative_to(root).as_posix()
                errors.append(f"core purity: {display} imports {target.as_posix()}")
    return errors


def frontend_layering_errors(root: Path) -> list[str]:
    """Enforce the backend-neutral RISC-V frontend ownership boundary."""
    src_root = root / "src"
    frontend_root = src_root / "frontends" / "riscv"
    errors: list[str] = []
    forbidden_layers = {"backends", "bench", "examples", "integrations", "interop", "tools"}
    for source in _zig_sources(frontend_root):
        text = source.read_text(encoding="utf-8")
        display = source.relative_to(root).as_posix()
        for imported in ZIG_IMPORT_RE.findall(text):
            target = _resolved_src_import(source, imported, src_root)
            if target is not None and target.parts and target.parts[0] in forbidden_layers:
                errors.append(f"frontend layering: {display} imports {target.as_posix()}")
        line_count = len(text.splitlines())
        if line_count > MANUAL_SOURCE_CEILING and not _generated_zig(text):
            errors.append(
                f"frontend layering: {display} has {line_count} lines "
                f"(manual ceiling {MANUAL_SOURCE_CEILING})"
            )
        code = ZIG_NON_CODE_RE.sub(" ", text)
        markers = sorted(set(ACTIVE_PLACEHOLDER_RE.findall(code)))
        if markers:
            errors.append(
                f"frontend layering: {display} contains active placeholder markers: "
                + ", ".join(markers)
            )
    return errors


def structure_errors(root: Path) -> list[str]:
    return core_purity_errors(root) + frontend_layering_errors(root)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
