"""Bind the normalized pilot capsule to pinned Sail theorem-backend output."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import codec, sail_lean_bridge, sail_translation
from .model import (
    SAIL_REPOSITORY,
    SAIL_REVISION,
    SAIL_VERSION,
    Paths,
    RefinementError,
)

# Two evidence grades, and only one of them can mint Sail output.
#   live-toolchain                  `collect_evidence`: pinned checkout, Sail
#                                   0.20.2, built simulator, generated backend.
#   carried-committed-sail-evidence `carried_evidence`: the committed manifest's
#                                   own provenance, re-checked against pinned
#                                   constants and re-hashed repository inputs,
#                                   and only ever able to reproduce the Sail
#                                   artifacts that are already committed.
# The grade is written into the manifest and receipts refuse the carried one.
LIVE_EVIDENCE = "live-toolchain"
CARRIED_EVIDENCE = "carried-committed-sail-evidence"
NORMALIZATION = (
    "checked generated-definition AST translation receipt for Team A "
    "UTYPE, ITYPE, and RTYPE selectors"
)
LEGACY_NORMALIZATION = "reviewed exact-hash LUI and ADDI expression capsule"

GENERATED_DEFINITION_HASHES = {
    "execute_UTYPE": "f746995b8c903140529bb742379c295bee8d95a02de2d730990dc77fe1cacf1c",
    "execute_ITYPE": "1d014d14c56ab01dc511fc36c8c6ee4dea56a63708257b8a5df451e7c6f6b17d",
    "execute_RTYPE": "01359d58d0543ce431b7315caf9961ea80329de2f017f2ea6cb205a7149cd628",
}
SOURCE_SLICE_HASHES = {
    "UTYPE": "a994f93a7ea421755ae439539d20b62fac52ab9c6517f18e9159d37b9481432d",
    "ITYPE": "d543047dde089e1175bce44a64d745d68e1c8cc37f61f442f86feea0fd0ffaa6",
    "RTYPE": "597df425d34ca5619049a2d5d5d6970cad7fa7ad6f22887c37fd19428be4b2e2",
}
PROFILE_PATH = Path("conformance/riscv/rv32im-sail-profile.json")
OVERRIDE_PATHS = (
    Path("conformance/riscv/sail-rv32im-override.json"),
    Path("conformance/riscv/sail-rv32im-tagged-options.json"),
)
PATCH_PATH = Path("conformance/riscv/sail-rvfi-zkvm-entry.patch")
PATCHED_SOURCE = Path("c_emulator/rvfi_dii.cpp")
MODEL_ENTRY = Path("model/riscv.sail_project")
SOURCE_FILE = Path("model/extensions/I/base_insts.sail")
BASE_CONFIGURATION = Path("build/config/rv32d_v256_e32.json")
EXACT_CONFIGURATION = Path("build/riscv-refinement/rv32im-zkvm-v1.json")
GENERATED_FILE = Path(
    "build/riscv-refinement/Lean_RV32IM/LeanRV32IM/InstsEnd.lean"
)
SIMULATOR = Path("build/c_emulator/sail_riscv_sim")

# Sail-side inputs that live in this repository, so a reused-evidence run can
# re-hash every one of them instead of trusting the committed manifest.
CARRIED_INPUTS = (PROFILE_PATH, *OVERRIDE_PATHS, PATCH_PATH)
# Sail artifacts a reused-evidence run may only ever reproduce byte for byte.
COMMITTED_CONFIGURATION = Path("generated/sail/rv32im-zkvm-v1.json")
COMMITTED_CAPSULE = Path("RiscvRefinement/Sail/Generated/Pilot.lean")
COMMITTED_DEFINITIONS = {
    name: Path("generated/sail/definitions") / f"{name}.lean"
    for name in GENERATED_DEFINITION_HASHES
}
COMMITTED_TRANSLATION_RECEIPT = Path(
    "generated/sail/translation-receipt-v1.json"
)
COMMITTED_MONAD_BRIDGE_RECEIPT = sail_lean_bridge.COMMITTED_RECEIPT


@dataclass(frozen=True)
class SailEvidence:
    # The live toolchain fields are None under carried evidence, which is why
    # `toolchain` (the receipt input) refuses anything but live evidence.
    source_root: Path | None
    compiler: Path | None
    compiler_sha256: str | None
    simulator_sha256: str | None
    generated_file: Path | None
    generated_file_sha256: str
    source_file_sha256: str
    model_entry_sha256: str
    base_configuration_sha256: str
    exact_configuration: bytes
    exact_configuration_sha256: str
    profile_file_sha256: dict[str, str]
    checkout_state: str
    definition_hashes: dict[str, str]
    definition_slices: dict[str, str]
    source_slice_hashes: dict[str, str]
    translation_receipt: dict[str, object]
    monad_bridge_receipt: dict[str, object]
    evidence_source: str = LIVE_EVIDENCE


def _run(
    argv: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
            if len(detail) > 4000:
                detail = "... " + detail[-4000:]
        raise RefinementError(
            f"command failed: {' '.join(argv)}" + (f": {detail}" if detail else "")
        ) from exc
    return completed.stdout.strip()


def _run_bytes(argv: list[str], cwd: Path | None = None) -> bytes:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RefinementError(f"command failed: {' '.join(argv)}") from exc


def _git_revision(root: Path) -> str:
    return _run(["git", "-C", str(root), "rev-parse", "HEAD"])


def _compiler_version(compiler: Path) -> str:
    output = _run([str(compiler), "--version"])
    match = re.search(r"\b(\d+\.\d+\.\d+)\b", output)
    if match is None:
        raise RefinementError(f"could not parse Sail version from {output!r}")
    return match.group(1)


def _profile(repository_root: Path) -> dict[str, object]:
    profile_path = repository_root / PROFILE_PATH
    profile = codec.load_json(profile_path)
    try:
        authority = profile["authorities"]["sail"]
        transport = profile["rvfi_transport"]
        configured_overrides = tuple(
            Path(path) for path in authority["configuration_overrides_in_order"]
        )
        if (
            profile["schema"] != "stwo-riscv-formal-profile-v1"
            or profile["name"] != "rv32im-zkvm-v1"
            or authority["repository"] != SAIL_REPOSITORY
            or authority["revision"] != SAIL_REVISION
            or authority["compiler"] != SAIL_VERSION
            or authority["base_configuration"] != "rv32"
            or authority["validated_isa_string"] != "rv32im"
            or configured_overrides != OVERRIDE_PATHS
            or Path(transport["patch"]["path"]) != PATCH_PATH
        ):
            raise RefinementError("normative RV32IM Sail profile drifted")
    except (KeyError, TypeError) as exc:
        raise RefinementError("normative RV32IM Sail profile is malformed") from exc
    patch_path = repository_root / PATCH_PATH
    if codec.sha256_file(patch_path) != transport["patch"]["sha256"]:
        raise RefinementError("normative Sail transport patch digest drifted")
    return profile


def _strip_line_comments(text: str) -> str:
    result: list[str] = []
    quoted = False
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if quoted:
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            result.append(character)
            index += 1
            continue
        if character == "/" and index + 1 < len(text) and text[index + 1] == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        result.append(character)
        index += 1
    if quoted:
        raise RefinementError("Sail base configuration has an unterminated string")
    return "".join(result)


def _relaxed_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(_strip_line_comments(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RefinementError(f"{path}: invalid Sail configuration") from exc
    if not isinstance(value, dict):
        raise RefinementError(f"{path}: Sail configuration must be an object")
    return value


def _merge_configuration(
    base: dict[str, object],
    override: dict[str, object],
) -> dict[str, object]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        current = result.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            result[key] = _merge_configuration(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def exact_configuration(repository_root: Path, source_root: Path) -> bytes:
    base_path = source_root / BASE_CONFIGURATION
    if not base_path.is_file():
        raise RefinementError(
            f"{base_path}: generated Sail base configuration is absent; "
            "prepare the pinned formal tools first"
        )
    merged = _relaxed_json(base_path)
    for relative in OVERRIDE_PATHS:
        merged = _merge_configuration(
            merged,
            codec.load_json(repository_root / relative),
        )
    try:
        if (
            merged["base"]["xlen"] != 32
            or merged["extensions"]["M"]["supported"] is not True
            or any(
                merged["extensions"][extension]["supported"] is not False
                for extension in ("A", "F", "D")
            )
            or merged["extensions"]["V"]["support_level"] != "Disabled"
        ):
            raise RefinementError("merged Sail configuration is not RV32IM")
    except (KeyError, TypeError) as exc:
        raise RefinementError("merged Sail configuration is malformed") from exc
    return codec.pretty_bytes(merged)


def _checkout_state(
    repository_root: Path,
    source_root: Path,
    profile: dict[str, object],
) -> str:
    status = _run(
        [
            "git",
            "-C",
            str(source_root),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ]
    )
    if not status:
        return "clean"
    expected = f"M {PATCHED_SOURCE.as_posix()}"
    if status != expected:
        raise RefinementError(
            f"pinned sail-riscv checkout has unexpected changes: {status!r}"
        )
    upstream = _run_bytes(
        [
            "git",
            "-C",
            str(source_root),
            "show",
            f"HEAD:{PATCHED_SOURCE.as_posix()}",
        ]
    )
    old = b"  return 0x80000000;"
    new = b"  return 0x00010000;"
    if upstream.count(old) != 1 or new in upstream:
        raise RefinementError("pinned Sail RVFI source shape drifted")
    if (source_root / PATCHED_SOURCE).read_bytes() != upstream.replace(old, new):
        raise RefinementError("Sail checkout contains more than the pinned RVFI patch")
    patch = profile["rvfi_transport"]["patch"]
    if codec.sha256_file(repository_root / PATCH_PATH) != patch["sha256"]:
        raise RefinementError("Sail RVFI patch identity drifted")
    return "rvfi-transport-patch-only"


def _extract_definition(text: str, name: str) -> str:
    marker = f"def {name} "
    try:
        start = text.index(marker)
    except ValueError as exc:
        raise RefinementError(f"generated Sail output has no {name}") from exc
    next_definition = re.search(r"\ndef [A-Za-z0-9_]+ ", text[start + 1 :])
    end = (
        start + 1 + next_definition.start()
        if next_definition is not None
        else len(text)
    )
    return text[start:end].rstrip() + "\n"


def _extract_source_slices(text: str) -> dict[str, str]:
    markers = {
        "UTYPE": (
            "union clause instruction = UTYPE",
            "// *****************************************************************\n\n// Jump",
        ),
        "ITYPE": (
            "union clause instruction = ITYPE",
            "// *****************************************************************\nunion clause instruction = SHIFTIOP",
        ),
        "RTYPE": (
            "union clause instruction = RTYPE",
            "// *****************************************************************\nunion clause instruction = LOAD",
        ),
    }
    result: dict[str, str] = {}
    for name, (start_marker, end_marker) in markers.items():
        try:
            start = text.index(start_marker)
            end = text.index(end_marker, start)
        except ValueError as exc:
            raise RefinementError(f"pinned Sail source has no complete {name} slice") from exc
        result[name] = text[start:end].rstrip() + "\n"
    return result


def _validate_semantic_shapes(definitions: dict[str, str]) -> None:
    utype = definitions["execute_UTYPE"]
    itype = definitions["execute_ITYPE"]
    rtype = definitions["execute_RTYPE"]
    required_utype = (
        "sign_extend (m := 32) (imm +++ 0x000#12)",
        "| .LUI => (pure off)",
        "| .AUIPC => (pure ((← (get_arch_pc ())) + off))",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    )
    required_itype = (
        "sign_extend (m := 32) imm",
        "| .ADDI => (pure ((← (rX_bits rs1)) + immext))",
        "| .SLTI => (pure (zero_extend (m := 32) (bool_to_bit (zopz0zI_s",
        "| .SLTIU =>",
        "| .ANDI => (pure ((← (rX_bits rs1)) &&& immext))",
        "| .ORI => (pure ((← (rX_bits rs1)) ||| immext))",
        "| .XORI => (pure ((← (rX_bits rs1)) ^^^ immext))",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    )
    required_rtype = (
        "| .ADD => (pure ((← (rX_bits rs1)) + (← (rX_bits rs2))))",
        "| .SLT =>",
        "| .SLTU =>",
        "| .AND => (pure ((← (rX_bits rs1)) &&& (← (rX_bits rs2))))",
        "| .OR => (pure ((← (rX_bits rs1)) ||| (← (rX_bits rs2))))",
        "| .XOR => (pure ((← (rX_bits rs1)) ^^^ (← (rX_bits rs2))))",
        "| .SUB => (pure ((← (rX_bits rs1)) - (← (rX_bits rs2))))",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    )
    for phrase in required_utype:
        if phrase not in utype:
            raise RefinementError(f"generated execute_UTYPE lost {phrase!r}")
    for phrase in required_itype:
        if phrase not in itype:
            raise RefinementError(f"generated execute_ITYPE lost {phrase!r}")
    for phrase in required_rtype:
        if phrase not in rtype:
            raise RefinementError(f"generated execute_RTYPE lost {phrase!r}")


def _translation_receipt(definitions: dict[str, str]) -> dict[str, object]:
    """Derive and validate the fail-closed pilot translation contract."""
    if set(definitions) != set(GENERATED_DEFINITION_HASHES):
        raise RefinementError(
            "generated Sail translation definition set drifted"
        )
    try:
        receipt = sail_translation.build_receipt(definitions)
    except sail_translation.SailTranslationError as exc:
        raise RefinementError(
            f"generated Sail definition translation failed: {exc}"
        ) from exc
    entries = receipt.get("definitions")
    if not isinstance(entries, dict):
        raise RefinementError("generated Sail translation receipt is malformed")
    for name, expected_digest in GENERATED_DEFINITION_HASHES.items():
        entry = entries.get(name)
        if (
            not isinstance(entry, dict)
            or entry.get("source_sha256") != expected_digest
            or entry.get("result_type") != "(SailM ExecutionResult)"
            or entry.get("selector_binder") != "op"
        ):
            raise RefinementError(
                f"generated Sail translation identity drifted for {name}"
            )
    if set(entries["execute_UTYPE"].get("selectors", {})) != {
        "AUIPC",
        "LUI",
    }:
        raise RefinementError(
            "generated execute_UTYPE selector coverage drifted"
        )
    if set(entries["execute_ITYPE"].get("selectors", {})) != {
        "ADDI",
        "ANDI",
        "ORI",
        "SLTI",
        "SLTIU",
        "XORI",
    }:
        raise RefinementError(
            "generated execute_ITYPE selector coverage drifted"
        )
    if set(entries["execute_RTYPE"].get("selectors", {})) != {
        "ADD",
        "AND",
        "OR",
        "SLL",
        "SLT",
        "SLTU",
        "SRA",
        "SRL",
        "SUB",
        "XOR",
    }:
        raise RefinementError(
            "generated execute_RTYPE selector coverage drifted"
        )

    def expected_effect(
        value: str,
        reads: list[str],
        *,
        reads_program_counter: bool = False,
    ) -> dict[str, object]:
        return {
            "memory_read": None,
            "memory_write": None,
            "next_pc": sail_translation.SEQUENTIAL_NEXT_PC,
            "reads_program_counter": reads_program_counter,
            "register_reads": reads,
            "register_write": {"target": "rd", "value": value},
            "retirement": "RETIRE_SUCCESS",
        }

    expected = {
        "execute_UTYPE": {
            "LUI": expected_effect(
                "(sign_extend (m := 32) (imm +++ 0x000#12))",
                [],
            ),
            "AUIPC": expected_effect(
                "((← (get_arch_pc ())) + "
                "(sign_extend (m := 32) (imm +++ 0x000#12)))",
                [],
                reads_program_counter=True,
            ),
        },
        "execute_ITYPE": {
            "ADDI": expected_effect(
                "((← (rX_bits rs1)) + (sign_extend (m := 32) imm))",
                ["rs1"],
            ),
            "SLTI": expected_effect(
                "(zero_extend (m := 32) (bool_to_bit "
                "(zopz0zI_s (← (rX_bits rs1)) "
                "(sign_extend (m := 32) imm))))",
                ["rs1"],
            ),
            "SLTIU": expected_effect(
                "(zero_extend (m := 32) (bool_to_bit "
                "(zopz0zI_u (← (rX_bits rs1)) "
                "(sign_extend (m := 32) imm))))",
                ["rs1"],
            ),
            "ANDI": expected_effect(
                "((← (rX_bits rs1)) &&& (sign_extend (m := 32) imm))",
                ["rs1"],
            ),
            "ORI": expected_effect(
                "((← (rX_bits rs1)) ||| (sign_extend (m := 32) imm))",
                ["rs1"],
            ),
            "XORI": expected_effect(
                "((← (rX_bits rs1)) ^^^ (sign_extend (m := 32) imm))",
                ["rs1"],
            ),
        },
        "execute_RTYPE": {
            "ADD": expected_effect(
                "((← (rX_bits rs1)) + (← (rX_bits rs2)))",
                ["rs1", "rs2"],
            ),
            "SUB": expected_effect(
                "((← (rX_bits rs1)) - (← (rX_bits rs2)))",
                ["rs1", "rs2"],
            ),
            "XOR": expected_effect(
                "((← (rX_bits rs1)) ^^^ (← (rX_bits rs2)))",
                ["rs1", "rs2"],
            ),
            "OR": expected_effect(
                "((← (rX_bits rs1)) ||| (← (rX_bits rs2)))",
                ["rs1", "rs2"],
            ),
            "AND": expected_effect(
                "((← (rX_bits rs1)) &&& (← (rX_bits rs2)))",
                ["rs1", "rs2"],
            ),
            "SLT": expected_effect(
                "(zero_extend (m := 32) (bool_to_bit "
                "(zopz0zI_s (← (rX_bits rs1)) (← (rX_bits rs2)))))",
                ["rs1", "rs2"],
            ),
            "SLTU": expected_effect(
                "(zero_extend (m := 32) (bool_to_bit "
                "(zopz0zI_u (← (rX_bits rs1)) (← (rX_bits rs2)))))",
                ["rs1", "rs2"],
            ),
        },
    }
    for definition, selectors in expected.items():
        for selector, effect in selectors.items():
            if entries[definition]["selectors"].get(selector) != effect:
                raise RefinementError(
                    f"generated {definition} {selector} normalization drifted"
                )
    return receipt


def _verify_translation_receipt(
    receipt: dict[str, object],
    definitions: dict[str, str],
) -> dict[str, object]:
    """Re-derive a carried receipt, then enforce the same pilot contract."""
    try:
        rederived = sail_translation.verify_receipt(receipt, definitions)
    except sail_translation.SailTranslationError as exc:
        raise RefinementError(
            f"committed Sail translation receipt is invalid: {exc}"
        ) from exc
    expected = _translation_receipt(definitions)
    if rederived != expected:
        raise RefinementError(
            "committed Sail translation receipt does not reproduce the "
            "pinned pilot translation"
        )
    return rederived
