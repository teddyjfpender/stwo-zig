"""Static candidate/promoted state and CP-11 receipt validation."""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

try:
    from riscv_trace_vectors_lib import admission as admission_policy
except ModuleNotFoundError:  # Imported as scripts.riscv_release_gate_lib in tests.
    from scripts.riscv_trace_vectors_lib import admission as admission_policy

try:
    from riscv_release_gate_lib import air_divergence
except ModuleNotFoundError:  # Imported as scripts.riscv_release_gate_lib in tests.
    from scripts.riscv_release_gate_lib import air_divergence


PINNED_ORACLE = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
ORACLE_REPOSITORY = "https://github.com/riscv/sail-riscv"
IMPLEMENTATION_REPOSITORY = "https://github.com/teddyjfpender/stwo-zig"
# Every boundary a CP-11 receipt must still report, in producer order.  The set
# is unchanged by the Stark-V demotion: a demoted boundary keeps its evidence,
# its per-case digests, and its place in the key manifest.  What changed is the
# verdict it is held to -- see PARITY_BOUNDARIES below.
BOUNDARIES = (
    "decode",
    "execution",
    "per_family_witness_rows",
    "program_tuples",
    "ordered_accesses",
    "public_values",
    "memory_roots",
    "poseidon2_vectors",
    "relation_tuples",
    "relation_sums",
    "shared_transcript_prefix",
)
# Boundaries for which pinned-oracle agreement is still the acceptance verdict.
# The complement is air_divergence.SUPERSEDED_BOUNDARIES, which may instead
# report a pinned divergence shape; see that module for why and for how a real
# regression stays distinguishable from the intended divergence.
PARITY_BOUNDARIES = tuple(
    name for name in BOUNDARIES if name not in air_divergence.SUPERSEDED_BOUNDARIES
)
NONEMPTY_RELATION_KEY = "nonempty_public_input"
ELF_CORPUS_BOUNDARIES = frozenset({
    "execution",
    "per_family_witness_rows",
    "program_tuples",
    "ordered_accesses",
    "public_values",
    "memory_roots",
    "relation_tuples",
    "relation_sums",
    "shared_transcript_prefix",
})
ELF_AGREEMENT_BOUNDARIES = ELF_CORPUS_BOUNDARIES - {
    "program_tuples", "memory_roots",
}
GENERATED_CORPUS_KEYS = {
    "decode": "decode/corpus",
    "poseidon2_vectors": "poseidon2_vectors/corpus",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_RECEIPT_AGE_SECONDS = 24 * 60 * 60
ZIG_IMPORT_RE = re.compile(r'@import\("([^"\n]+)"\)')
ZIG_NON_CODE_RE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', re.DOTALL)
ACTIVE_PLACEHOLDER_RE = re.compile(r"\b(?:legacy|placeholder|silent)\b")
MANUAL_SOURCE_CEILING = 850
PROOF_SUPPORTED = admission_policy.SUPPORTED
BALANCED_RELATION_MODE = "balanced_full"
NONEMPTY_RELATION_MODE = "nonempty_public_input"
NONEMPTY_RELATION_CASE = "public_io_partial_word"
NONEMPTY_RELATION_GENERATOR = "scripts/riscv_release_oracle_lib/public_input_fixture.py"
NONEMPTY_RELATION_ELF_SHA256 = (
    "a55facfb5444038a6544a499cfbf2c4845e73e032a5ebda882effc431e8115ee"
)
NONEMPTY_RELATION_INPUT_SHA256 = (
    "47e4ee7f211f73265dd17658f6e21c1318bd6c81f37598e20a2756299542efcf"
)
NONEMPTY_RELATION_PUBLIC_FIELDS = (
    "initial_pc", "final_pc", "clock", "initial_regs", "final_regs",
    "reg_last_clock", "program_root", "initial_rw_root", "final_rw_root",
    "io_entries",
)
ALLOWED_ACTIVE_DIVERGENCES = frozenset({
    ("RISC-V", "PCS geometry"),
    ("RISC-V", "Interaction transcript"),
    ("RISC-V", "RV32IM decode boundary"),
    air_divergence.LEDGER_ROW,
})
# Rows whose absence is itself a failure. The AIR-soundness row is required, not
# merely allowed: deleting it would hide the fact that the pinned legacy oracle
# admits the under-constraints this branch closed, and re-matching that oracle
# would reintroduce them. A demoted CP-11 boundary may only cite a row present
# here.
REQUIRED_ARCHITECTURAL_DIVERGENCES = frozenset({
    ("RISC-V", "PCS geometry"),
    ("RISC-V", "Interaction transcript"),
    air_divergence.LEDGER_ROW,
})
KNOWN_PIN_DOCUMENTED_LIMITATIONS: dict[str, frozenset[tuple[str, str]]] = {}


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


def divergence_ledger_errors(text: str, pinned_oracle: str = PINNED_ORACLE) -> list[str]:
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

    for key in KNOWN_PIN_DOCUMENTED_LIMITATIONS.get(pinned_oracle, frozenset()):
        if key not in rows:
            errors.append(
                "known oracle limitation lacks its mandatory documented divergence: "
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
        "conformance/2026-07-18-riscv-release-goal.md",
        "conformance/divergence-log.md",
        "scripts/riscv_release_gate.py",
        "scripts/riscv_formal_tools.py",
        "scripts/riscv_arch_tests.py",
        "scripts/riscv_staged_smoke.py",
        "scripts/riscv_trace_vectors.py",
        "src/frontends/riscv/air/semantics/mulh.zig",
        "src/products/riscv_cpu/capabilities.zig",
    )
    errors = [f"missing required release artifact: {path}" for path in required if not (root / path).is_file()]
    registry = (root / "src/tools/prove/registry.zig").read_text(encoding="utf-8")
    capability = (root / "src/products/riscv_cpu/capabilities.zig").read_text(encoding="utf-8")
    artifact = (root / "src/interop/riscv_artifact.zig").read_text(encoding="utf-8")
    cli = (root / "src/tools/prove/cli.zig").read_text(encoding="utf-8")
    errors.extend(phase_errors(phase, registry, capability, artifact, cli))
    errors.extend(divergence_errors(root))
    autoresearch = root / "autoresearch/MANIFEST.json"
    if autoresearch.is_file():
        payload = json.loads(autoresearch.read_text(encoding="utf-8"))
        groups = payload.get("workload_registry", {}).get("groups", {})
        riscv = groups.get("riscv") if isinstance(groups, dict) else None
        if not isinstance(riscv, dict):
            errors.append("autoresearch RISC-V workload group is missing")
        elif riscv.get("enabled") is not False or not str(riscv.get("disabled_reason", "")).strip():
            errors.append("autoresearch RISC-V workload group must remain disabled through RF-01")
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


def _sha(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        errors.append(f"{label} is not a lowercase SHA-256 digest")


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def trace_vector_contract() -> tuple[
    tuple[str, ...], dict[str, dict[str, str]], dict[str, str]
]:
    root = Path(__file__).resolve().parents[2]
    payload = json.loads(
        (root / "vectors/riscv_elfs/trace_vectors.json").read_text(encoding="utf-8")
    )
    vectors = payload.get("vectors")
    if not isinstance(vectors, list):
        raise ValueError("trace-vector manifest has no positive vector list")
    names = tuple(
        vector.get("name") if isinstance(vector, dict) else None for vector in vectors
    )
    if not names or any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
        raise ValueError("trace-vector manifest has invalid or duplicate names")
    expected = admission_policy.for_programs(names)
    admission_errors = admission_policy.errors(vectors, expected)
    if admission_errors:
        raise ValueError(
            "trace-vector proof-admission policy is invalid: " + "; ".join(admission_errors)
        )
    elf_digests = {vector["name"]: vector.get("elf_sha256") for vector in vectors}
    if any(SHA256_RE.fullmatch(digest or "") is None for digest in elf_digests.values()):
        raise ValueError("trace-vector manifest has an invalid ELF digest")
    return names, expected, elf_digests


def trace_vector_names() -> tuple[str, ...]:
    return trace_vector_contract()[0]


def expected_case_result_keys(vector_names: tuple[str, ...]) -> list[str]:
    keys = [f"{boundary}/aggregate" for boundary in BOUNDARIES]
    for boundary in BOUNDARIES:
        if boundary in ELF_CORPUS_BOUNDARIES:
            keys.extend(f"{boundary}/{name}" for name in vector_names)
            if boundary in {"relation_tuples", "relation_sums"}:
                keys.append(f"{boundary}/{NONEMPTY_RELATION_CASE}")
        elif boundary in GENERATED_CORPUS_KEYS:
            keys.append(GENERATED_CORPUS_KEYS[boundary])
    return sorted(keys)


def _nonempty_relation_errors(
    case: object,
    boundary: str,
    candidate: str,
    witness_digest: object,
    *,
    superseded: bool = False,
) -> list[str]:
    """Validate the nonempty-public-input relation case.

    ``superseded`` relaxes exactly two obligations -- pinned-oracle agreement and
    the absence of a localized difference -- because this case runs the same AIR
    comparison as the boundary that carries it. Every self-consistency
    obligation (balance to zero, public-data agreement, candidate binding,
    corpus binding) is unaffected: those do not depend on the legacy oracle.
    """
    label = f"boundary {boundary}/{NONEMPTY_RELATION_CASE}"
    if not isinstance(case, dict):
        return [f"{label} is missing"]
    errors: list[str] = []
    expected = {
        "name": NONEMPTY_RELATION_CASE,
        "generator": NONEMPTY_RELATION_GENERATOR,
        "elf_sha256": NONEMPTY_RELATION_ELF_SHA256,
        "input_sha256": NONEMPTY_RELATION_INPUT_SHA256,
        "input_len": 9,
        "proof_admitted": True,
        "evidence_mode": NONEMPTY_RELATION_MODE,
        "component_count": 27,
        "relation_count": 12,
    }
    if not superseded:
        expected["agree"] = True
    for field, value in expected.items():
        if case.get(field) != value or type(case.get(field)) is not type(value):
            errors.append(f"{label} has invalid {field}")
    if not superseded and (
        "evidence_error" in case or case.get("first_divergence") is not None
    ):
        errors.append(f"{label} records disagreement")
    for field in ("rust_sha256", "zig_sha256"):
        _sha(case.get(field), f"{label} {field}", errors)
    public = case.get("public_data")
    if not isinstance(public, dict) or public.get("agree") is not True:
        errors.append(f"{label} lacks public-data agreement")
    else:
        if public.get("fields") != list(NONEMPTY_RELATION_PUBLIC_FIELDS):
            errors.append(f"{label} public-data fields are incomplete")
        if public.get("mismatches") != []:
            errors.append(f"{label} public-data mismatches are nonempty")
        _sha(public.get("normalized_sha256"), f"{label} public data", errors)
    binding = case.get("zig_binding")
    binding_expected = {
        "implementation_commit": candidate,
        "implementation_dirty": False,
        "oracle_commit": PINNED_ORACLE,
        "elf_sha256": NONEMPTY_RELATION_ELF_SHA256,
        "input_sha256": NONEMPTY_RELATION_INPUT_SHA256,
        "witness_layout_sha256": witness_digest,
    }
    if not isinstance(binding, dict):
        errors.append(f"{label} lacks a Zig diagnostic binding")
    else:
        for field, value in binding_expected.items():
            if binding.get(field) != value:
                errors.append(f"{label} binding has invalid {field}")
        for field in (
            "diagnostic_preprocessed_commitment", "diagnostic_main_commitment",
            "diagnostic_interaction_commitment",
        ):
            _sha(binding.get(field), f"{label} binding {field}", errors)
    expected_observation = (
        "canonical_nonzero_tuple_streams"
        if boundary == "relation_tuples"
        else "all_component_prefixes_and_relation_domains"
    )
    if case.get("observation") != expected_observation:
        errors.append(f"{label} has the wrong observation")
    if boundary == "relation_sums":
        if case.get("public_relation_count") != 3:
            errors.append(f"{label} does not cover all public relation domains")
        if case.get("public_memory_sum_nonzero") is not True:
            errors.append(f"{label} has no nonzero public memory compensation")
        if case.get("balanced_sum") != [0, 0, 0, 0]:
            errors.append(f"{label} does not balance to zero")
    return errors


def _relation_case_errors(
    case: dict,
    boundary: str,
    admission: dict[str, str],
    *,
    superseded: bool = False,
) -> list[str]:
    """Validate one relation-boundary corpus case.

    ``superseded`` drops only the pinned-oracle agreement claim; the divergence
    it is allowed to report is bounded separately by
    ``air_divergence.coverage_errors``.
    """
    label = f"boundary case {boundary}/{case.get('name')}"
    errors: list[str] = []
    if case.get("proof_admission") != admission:
        errors.append(f"{label} relabels the live proof-admission policy")
    if admission.get("status") != PROOF_SUPPORTED:
        return [f"{label} uses an unknown proof-admission status"]
    if case.get("evidence_mode") != BALANCED_RELATION_MODE:
        errors.append(f"{label} is not a full balanced relation comparison")
    if case.get("proof_admitted") is not True:
        errors.append(f"{label} has an invalid proof-admission verdict")
    if not superseded and case.get("agree") is not True:
        errors.append(f"{label} does not attest balanced agreement")
    if "limitation_evidence" in case or "comparison_outcome" in case:
        errors.append(f"{label} contains obsolete Stark-V limitation evidence")
    return errors


def receipt_errors(
    receipt: dict[str, Any],
    candidate: str,
    *,
    now: int | None = None,
    vector_names: tuple[str, ...] | None = None,
) -> list[str]:
    """Validate the full CP-11 evidence contract, not only its verdict bit."""
    errors: list[str] = []
    try:
        live_names, live_admission, live_elf_digests = trace_vector_contract()
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        errors.append(f"live trace-vector contract is invalid: {error}")
        live_names, live_admission, live_elf_digests = (), {}, {}
    if vector_names is None:
        names = live_names
        admissions = live_admission
        elf_digests = live_elf_digests
    else:
        names = vector_names
        admissions = (
            live_admission
            if vector_names == live_names
            else {name: {"status": PROOF_SUPPORTED} for name in vector_names}
        )
        elf_digests = live_elf_digests if vector_names == live_names else {}
    if COMMIT_RE.fullmatch(candidate) is None:
        errors.append("candidate is not a full lowercase Git commit")
    if receipt.get("schema") != "riscv-oracle-receipt-v2":
        errors.append("unknown oracle receipt schema")
    if receipt.get("candidate_commit") != candidate:
        errors.append("oracle receipt belongs to another candidate")
    if receipt.get("verdict") != "PASS":
        errors.append(f"oracle receipt verdict is {receipt.get('verdict')!r}")

    oracle = receipt.get("oracle")
    if not isinstance(oracle, dict):
        errors.append("oracle provenance is missing")
        oracle = {}
    if oracle.get("repository") != ORACLE_REPOSITORY:
        errors.append("oracle repository identity is not pinned")
    if oracle.get("commit") != PINNED_ORACLE:
        errors.append("oracle commit identity is not pinned")
    if oracle.get("clean") is not True:
        errors.append("oracle receipt does not attest a clean source tree")
    for field in ("tree_digest_sha256", "lockfile_sha256", "executable_sha256"):
        _sha(oracle.get(field), f"oracle.{field}", errors)
    for field in ("toolchain", "build_command", "build_mode", "host_arch", "host_os"):
        if not isinstance(oracle.get(field), str) or not oracle[field].strip():
            errors.append(f"oracle.{field} is missing")
    if "--locked" not in str(oracle.get("build_command", "")):
        errors.append("oracle build command does not enforce locked dependencies")
    if not isinstance(oracle.get("submodule_status"), list):
        errors.append("oracle submodule state is missing")
    overlay = oracle.get("adapter_overlay")
    if not isinstance(overlay, dict) or not isinstance(overlay.get("path"), str):
        errors.append("oracle adapter overlay identity is missing")
    else:
        _sha(overlay.get("sha256"), "oracle adapter overlay", errors)

    implementation = receipt.get("implementation")
    if not isinstance(implementation, dict):
        errors.append("Zig implementation provenance is missing")
        implementation = {}
    if implementation.get("repository") != IMPLEMENTATION_REPOSITORY:
        errors.append("Zig implementation repository identity is not pinned")
    if implementation.get("commit") != candidate:
        errors.append("Zig implementation executable belongs to another candidate")
    if implementation.get("clean") is not True:
        errors.append("Zig implementation executable does not attest a clean source tree")
    executables = implementation.get("executables")
    if not isinstance(executables, dict) or set(executables) != {
        "riscv-trace-dump", "stwo-zig",
    }:
        errors.append("Zig implementation executable manifest is incomplete or non-canonical")
    else:
        for name, digest in executables.items():
            _sha(digest, f"Zig executable {name}", errors)

    created = receipt.get("created_at_unix")
    current = int(time.time()) if now is None else now
    if not isinstance(created, int):
        errors.append("receipt creation time is missing")
    elif created > current + 300 or current - created > MAX_RECEIPT_AGE_SECONDS:
        errors.append("oracle receipt is expired or from the future")
    _sha(receipt.get("witness_layout_digest_sha256"), "witness layout digest", errors)
    _sha(receipt.get("corpus_digest_sha256"), "corpus digest", errors)

    boundaries = receipt.get("boundaries")
    if not isinstance(boundaries, dict):
        errors.append("boundary results are missing")
        boundaries = {}
    status_errors, superseded = air_divergence.status_errors(boundaries, BOUNDARIES)
    errors.extend(status_errors)
    errors.extend(air_divergence.coverage_errors(
        boundaries, superseded, NONEMPTY_RELATION_KEY
    ))
    for name in ("relation_tuples", "relation_sums"):
        boundary = boundaries.get(name)
        case = boundary.get(NONEMPTY_RELATION_KEY) if isinstance(boundary, dict) else None
        errors.extend(_nonempty_relation_errors(
            case, name, candidate, receipt.get("witness_layout_digest_sha256"),
            superseded=name in superseded,
        ))

    expected_keys = expected_case_result_keys(names)
    declared_keys = receipt.get("expected_case_result_keys")
    if declared_keys != expected_keys:
        errors.append("expected case-result key manifest is incomplete or non-canonical")
    digests = receipt.get("case_result_digests")
    if not isinstance(digests, dict):
        errors.append("per-case result digests are missing")
    else:
        if sorted(digests) != expected_keys:
            errors.append("case-result digest keys do not exactly cover the declared corpus")
        for name, digest in digests.items():
            _sha(digest, f"case result {name}", errors)
        for boundary in BOUNDARIES:
            aggregate = f"{boundary}/aggregate"
            if aggregate in digests and boundary in boundaries:
                if digests[aggregate] != _canonical_digest(boundaries[boundary]):
                    errors.append(f"aggregate digest does not bind boundary {boundary}")

        for boundary_name in ELF_CORPUS_BOUNDARIES:
            boundary = boundaries.get(boundary_name)
            cases = boundary.get("corpus") if isinstance(boundary, dict) else None
            if not isinstance(cases, list):
                errors.append(f"boundary {boundary_name} has no per-corpus evidence")
                continue
            case_names = tuple(
                case.get("name") if isinstance(case, dict) else None for case in cases
            )
            if case_names != names:
                errors.append(
                    f"boundary {boundary_name} corpus is incomplete, duplicated, or non-canonical"
                )
                continue
            for case in cases:
                key = f"{boundary_name}/{case['name']}"
                expected_elf = elf_digests.get(case["name"])
                if (
                    boundary_name in {"relation_tuples", "relation_sums"}
                    and expected_elf is not None
                    and case.get("elf_sha256") != expected_elf
                ):
                    errors.append(f"boundary case {key} is not bound to the live ELF digest")
                if digests.get(key) != _canonical_digest(case):
                    errors.append(f"case-result digest does not bind {key}")
                if (
                    boundary_name in ELF_AGREEMENT_BOUNDARIES
                    and boundary_name not in superseded
                    and case.get("agree") is not True
                ):
                    errors.append(f"boundary case {key} does not attest agreement")
                if boundary_name in {"relation_tuples", "relation_sums"}:
                    expected_admission = admissions.get(case["name"])
                    if expected_admission is None:
                        errors.append(f"boundary case {key} has no live admission policy")
                    else:
                        errors.extend(_relation_case_errors(
                            case, boundary_name, expected_admission,
                            superseded=boundary_name in superseded,
                        ))
            if boundary_name in {"relation_tuples", "relation_sums"}:
                special = boundary.get(NONEMPTY_RELATION_KEY)
                key = f"{boundary_name}/{NONEMPTY_RELATION_CASE}"
                if isinstance(special, dict) and digests.get(key) != _canonical_digest(special):
                    errors.append(f"case-result digest does not bind {key}")
        for boundary_name, key in GENERATED_CORPUS_KEYS.items():
            boundary = boundaries.get(boundary_name)
            if isinstance(boundary, dict) and digests.get(key) != _canonical_digest(boundary):
                errors.append(f"case-result digest does not bind {key}")
    return errors


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
