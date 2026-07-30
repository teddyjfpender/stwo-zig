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


def discover_source(explicit: Path | None, repository_root: Path) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    configured = os.environ.get("STWO_SAIL_RISCV_DIR")
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        [
            repository_root / "zig-out" / "riscv-refinement" / "sail-riscv",
            Path("/tmp/stwo-riscv-formal/source/sail-riscv"),
        ]
    )
    for candidate in candidates:
        if (candidate / ".git").exists() and (candidate / "model").is_dir():
            return candidate.resolve()
    raise RefinementError(
        "pinned sail-riscv checkout not found; pass --sail-riscv-dir or set "
        "STWO_SAIL_RISCV_DIR"
    )


def discover_compiler(explicit: Path | None) -> Path:
    if explicit is not None:
        candidate = explicit
    elif os.environ.get("SAIL"):
        candidate = Path(os.environ["SAIL"])
    else:
        found = shutil.which("sail")
        if found is None:
            fallback = Path.home() / ".opam" / "default" / "bin" / "sail"
            candidate = fallback
        else:
            candidate = Path(found)
    if not candidate.is_file():
        raise RefinementError("Sail compiler not found; pass --sail-bin")
    return candidate.resolve()


def _generated_file(source_root: Path, explicit: Path | None) -> Path:
    expected = (source_root / GENERATED_FILE).resolve()
    candidate = explicit.resolve() if explicit is not None else expected
    if candidate != expected:
        raise RefinementError(
            f"generated Sail file must be the exact RV32IM output {expected}"
        )
    if not candidate.is_file():
        raise RefinementError(
            "generated RV32IM Lean model is absent; run "
            "scripts/riscv_refinement.py prepare-sail"
        )
    return candidate


def _validate_exact_configuration(
    source_root: Path,
    configuration_path: Path,
) -> tuple[Path, str]:
    simulator = source_root / SIMULATOR
    if not simulator.is_file():
        raise RefinementError(
            f"{simulator}: pinned Sail simulator is absent; prepare the formal "
            "tools first"
        )
    _run(
        [
            str(simulator),
            "--config",
            str(configuration_path),
            "--validate-config",
        ]
    )
    isa = _run(
        [
            str(simulator),
            "--config",
            str(configuration_path),
            "--print-isa-string",
        ]
    )
    if isa.splitlines()[-1] != "rv32im":
        raise RefinementError(
            f"exact Sail configuration reports {isa!r}, expected rv32im"
        )
    resolved = simulator.resolve()
    return resolved, codec.sha256_file(resolved)


def prepare_exact_backend(
    repository_root: Path,
    source_root: Path | None,
    compiler: Path | None,
    force: bool,
) -> SailEvidence:
    root = discover_source(source_root, repository_root)
    profile = _profile(repository_root)
    revision = _git_revision(root)
    if revision != SAIL_REVISION:
        raise RefinementError(
            f"sail-riscv revision {revision} does not match pin {SAIL_REVISION}"
        )
    _checkout_state(repository_root, root, profile)
    sail_bin = discover_compiler(compiler)
    version = _compiler_version(sail_bin)
    if version != SAIL_VERSION:
        raise RefinementError(
            f"Sail compiler {version} does not match required {SAIL_VERSION}"
        )

    configuration = exact_configuration(repository_root, root)
    configuration_path = root / EXACT_CONFIGURATION
    changed = (
        not configuration_path.is_file()
        or configuration_path.read_bytes() != configuration
    )
    codec.atomic_write(configuration_path, configuration)
    _validate_exact_configuration(root, configuration_path)

    generated = root / GENERATED_FILE
    if force or changed or not generated.is_file():
        generated.parent.parent.parent.mkdir(parents=True, exist_ok=True)
        output_root = root / "build" / "riscv-refinement"
        memo_root = output_root / "sail_smt_cache"
        output_root.mkdir(parents=True, exist_ok=True)
        if memo_root.is_dir():
            if any(memo_root.iterdir()):
                raise RefinementError(
                    f"{memo_root}: Sail memo path must be a file, not a "
                    "nonempty directory"
                )
            memo_root.rmdir()
        _run(
            [
                str(sail_bin),
                "--strict-var",
                "--strict-bitvector",
                "--strict-exponentials",
                "--require-version",
                SAIL_VERSION,
                "--memo-z3-path",
                str(memo_root),
                "--config",
                str(configuration_path),
                "--lean",
                "--memo-z3",
                "--lean-output-dir",
                str(output_root),
                "--lean-force-output",
                "--lean-non-beq-type",
                "instruction",
                "--lean-non-beq-type",
                "ExecutionResult",
                "--lean-non-beq-type",
                "Step",
                "--lean-noncomputable",
                "--lean-noncomputable-function",
                "encdec_forwards",
                "--lean-noncomputable-function",
                "encdec_backwards",
                "--lean-noncomputable-function",
                "encdec_forwards_matches",
                "--lean-noncomputable-function",
                "encdec_backwards_matches",
                "--lean-noncomputable-function",
                "encdec_compressed_forwards",
                "--lean-noncomputable-function",
                "encdec_compressed_backwards",
                "--lean-noncomputable-function",
                "encdec_compressed_forwards_matches",
                "--lean-noncomputable-function",
                "encdec_compressed_backwards_matches",
                "--lean-import-file",
                "../handwritten_support/RiscvExtras.lean",
                "-o",
                "Lean_RV32IM",
                "--all-modules",
                MODEL_ENTRY.name,
            ],
            cwd=root / "model",
            timeout=1800,
        )
    return collect_evidence(
        repository_root,
        root,
        sail_bin,
        generated,
    )


def collect_evidence(
    repository_root: Path,
    source_root: Path | None,
    compiler: Path | None,
    generated_file: Path | None,
) -> SailEvidence:
    root = discover_source(source_root, repository_root)
    profile = _profile(repository_root)
    revision = _git_revision(root)
    if revision != SAIL_REVISION:
        raise RefinementError(
            f"sail-riscv revision {revision} does not match pin {SAIL_REVISION}"
        )
    sail_bin = discover_compiler(compiler)
    version = _compiler_version(sail_bin)
    if version != SAIL_VERSION:
        raise RefinementError(
            f"Sail compiler {version} does not match required {SAIL_VERSION}"
        )
    checkout_state = _checkout_state(repository_root, root, profile)
    configuration = exact_configuration(repository_root, root)
    configuration_path = root / EXACT_CONFIGURATION
    if (
        not configuration_path.is_file()
        or configuration_path.read_bytes() != configuration
    ):
        raise RefinementError(
            "exact RV32IM Sail configuration is absent or stale; run "
            "scripts/riscv_refinement.py prepare-sail"
        )
    simulator, simulator_sha256 = _validate_exact_configuration(
        root,
        configuration_path,
    )
    generated = _generated_file(root, generated_file)
    source = root / SOURCE_FILE
    generated_text = generated.read_text(encoding="utf-8")
    source_text = source.read_text(encoding="utf-8")
    definitions = {
        name: _extract_definition(generated_text, name)
        for name in GENERATED_DEFINITION_HASHES
    }
    definition_hashes = {
        name: codec.sha256_bytes(block.encode("utf-8"))
        for name, block in definitions.items()
    }
    if definition_hashes != GENERATED_DEFINITION_HASHES:
        raise RefinementError(
            "pinned Sail theorem-backend definitions drifted; review before "
            "updating the normalized capsule"
        )
    slices = _extract_source_slices(source_text)
    slice_hashes = {
        name: codec.sha256_bytes(block.encode("utf-8"))
        for name, block in slices.items()
    }
    if slice_hashes != SOURCE_SLICE_HASHES:
        raise RefinementError(
            "pinned Sail source slices drifted; review before updating the bridge"
        )
    _validate_semantic_shapes(definitions)
    translation_receipt = _translation_receipt(definitions)
    profile_files = (PROFILE_PATH, *OVERRIDE_PATHS, PATCH_PATH)
    generated_file_sha256 = codec.sha256_file(generated)
    monad_bridge_receipt = sail_lean_bridge.verify(
        Paths(repository_root),
        generated,
        generated_file_sha256,
    )
    return SailEvidence(
        source_root=root,
        compiler=sail_bin,
        compiler_sha256=codec.sha256_file(sail_bin),
        simulator_sha256=simulator_sha256,
        generated_file=generated,
        generated_file_sha256=generated_file_sha256,
        source_file_sha256=codec.sha256_file(source),
        model_entry_sha256=codec.sha256_file(root / MODEL_ENTRY),
        base_configuration_sha256=codec.sha256_file(root / BASE_CONFIGURATION),
        exact_configuration=configuration,
        exact_configuration_sha256=codec.sha256_bytes(configuration),
        profile_file_sha256={
            relative.as_posix(): codec.sha256_file(repository_root / relative)
            for relative in profile_files
        },
        checkout_state=checkout_state,
        definition_hashes=definition_hashes,
        definition_slices=definitions,
        source_slice_hashes=slice_hashes,
        translation_receipt=translation_receipt,
        monad_bridge_receipt=monad_bridge_receipt,
        evidence_source=LIVE_EVIDENCE,
    )


def _carried_digest(carried: dict[str, object], key: str) -> str:
    value = carried.get(key)
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RefinementError(
            f"committed Sail provenance {key} is not a sha256 digest"
        )
    return value


def _carried_base_pins(carried: dict[str, object]) -> None:
    """Check immutable provenance shared by normal reuse and capture."""
    pinned: dict[str, object] = {
        "repository": SAIL_REPOSITORY,
        "revision": SAIL_REVISION,
        "compiler_version": SAIL_VERSION,
        "architectural_profile": "rv32im-zkvm-v1",
        "validated_isa_string": "rv32im",
        "model_entry": MODEL_ENTRY.as_posix(),
        "base_configuration": BASE_CONFIGURATION.as_posix(),
        "exact_configuration": EXACT_CONFIGURATION.as_posix(),
        "source_file": SOURCE_FILE.as_posix(),
        "generated_backend_file": GENERATED_FILE.as_posix(),
        "generated_definition_sha256": GENERATED_DEFINITION_HASHES,
        "source_slice_sha256": SOURCE_SLICE_HASHES,
    }
    for key, expected in pinned.items():
        if carried.get(key) != expected:
            raise RefinementError(
                f"committed Sail provenance {key} does not match the pin in "
                f"scripts/riscv_refinement_lib/sail.py: "
                f"{carried.get(key)!r} != {expected!r}"
            )
    if carried.get("checkout_state") not in ("clean", "rvfi-transport-patch-only"):
        raise RefinementError(
            "committed Sail provenance names an unknown checkout state"
        )
    if carried.get("evidence_source", LIVE_EVIDENCE) not in (
        LIVE_EVIDENCE,
        CARRIED_EVIDENCE,
    ):
        raise RefinementError(
            "committed Sail provenance names an unknown evidence source"
        )


def _carried_pins(carried: dict[str, object]) -> None:
    """Every reusable field is pinned or re-derived, never trusted from JSON."""
    _carried_base_pins(carried)
    pinned: dict[str, object] = {
        "normalization": NORMALIZATION,
        "generated_monad_normalization_theorem": True,
        "generated_step_loop_framing_theorem": False,
    }
    for key, expected in pinned.items():
        if carried.get(key) != expected:
            raise RefinementError(
                f"committed Sail provenance {key} does not match the pin in "
                f"scripts/riscv_refinement_lib/sail.py: "
                f"{carried.get(key)!r} != {expected!r}"
            )
    translation = carried.get("generated_ast_translation_receipt")
    if (
        not isinstance(translation, dict)
        or translation.get("artifact")
        != COMMITTED_TRANSLATION_RECEIPT.as_posix()
        or translation.get("schema_version")
        != sail_translation.SCHEMA_VERSION
        or translation.get("parser_version")
        != sail_translation.PARSER_VERSION
    ):
        raise RefinementError(
            "committed Sail provenance translation receipt does not match "
            "the pinned artifact/schema/parser"
        )
    bridge = carried.get("generated_monad_bridge_receipt")
    if (
        not isinstance(bridge, dict)
        or bridge.get("artifact")
        != COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()
        or bridge.get("schema_version")
        != sail_lean_bridge.SCHEMA_VERSION
    ):
        raise RefinementError(
            "committed Sail provenance monad bridge receipt does not match "
            "the pinned artifact/schema"
        )


def _carried_inputs(paths: Paths, carried: dict[str, object]) -> dict[str, str]:
    """Re-hash every Sail input the committed provenance names in this repo."""
    digests = carried.get("profile_file_sha256")
    expected = {relative.as_posix() for relative in CARRIED_INPUTS}
    if not isinstance(digests, dict) or set(digests) != expected:
        raise RefinementError(
            "committed Sail provenance names an unexpected profile input set"
        )
    rehashed: dict[str, str] = {}
    for relative in CARRIED_INPUTS:
        path = paths.root / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"{relative.as_posix()}: Sail input named by the committed "
                "provenance is absent; reused evidence cannot be checked"
            )
        actual = codec.sha256_file(path)
        if actual != digests[relative.as_posix()]:
            raise RefinementError(
                f"{relative.as_posix()}: Sail input changed since the committed "
                f"provenance ({actual} != {digests[relative.as_posix()]}); "
                "re-derive the evidence with the live Sail toolchain"
            )
        rehashed[relative.as_posix()] = actual
    return rehashed


def _carried_configuration(
    paths: Paths,
    manifest: dict[str, object],
    carried: dict[str, object],
) -> bytes:
    """The reused exact configuration is the committed artifact, byte for byte."""
    path = paths.formal / COMMITTED_CONFIGURATION
    if path.is_symlink() or not path.is_file():
        raise RefinementError(
            f"{COMMITTED_CONFIGURATION.as_posix()}: committed exact Sail "
            "configuration is absent; reused evidence cannot be checked"
        )
    configuration = path.read_bytes()
    digest = codec.sha256_bytes(configuration)
    if digest != _carried_digest(carried, "exact_configuration_sha256"):
        raise RefinementError(
            f"{COMMITTED_CONFIGURATION.as_posix()}: committed exact Sail "
            "configuration does not match the committed provenance digest"
        )
    artifacts = manifest.get("artifacts")
    if (
        not isinstance(artifacts, dict)
        or artifacts.get(COMMITTED_CONFIGURATION.as_posix()) != digest
    ):
        raise RefinementError(
            f"{COMMITTED_CONFIGURATION.as_posix()}: committed manifest artifact "
            "digest does not match the committed exact Sail configuration"
        )
    return configuration


def _carried_translation(
    paths: Paths,
    manifest: dict[str, object],
) -> tuple[dict[str, str], dict[str, object]]:
    """Re-hash definition slices and re-derive their checked receipt."""
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RefinementError(
            "committed manifest has no generated artifact digest map"
        )
    definitions: dict[str, str] = {}
    for name, relative in COMMITTED_DEFINITIONS.items():
        path = paths.formal / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"{relative.as_posix()}: committed generated Sail definition "
                "slice is absent; reused evidence cannot be checked"
            )
        try:
            definitions[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RefinementError(
                f"{relative.as_posix()}: generated Sail definition is unreadable"
            ) from exc
        digest = codec.sha256_bytes(definitions[name].encode("utf-8"))
        if (
            digest != GENERATED_DEFINITION_HASHES[name]
            or artifacts.get(relative.as_posix()) != digest
        ):
            raise RefinementError(
                f"{relative.as_posix()}: generated Sail definition digest "
                "does not match the pinned backend and manifest"
            )
    receipt_path = paths.formal / COMMITTED_TRANSLATION_RECEIPT
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RefinementError(
            f"{COMMITTED_TRANSLATION_RECEIPT.as_posix()}: committed Sail "
            "translation receipt is absent; reused evidence cannot be checked"
        )
    receipt = codec.load_json(receipt_path)
    if receipt_path.read_bytes() != codec.pretty_bytes(receipt):
        raise RefinementError(
            f"{COMMITTED_TRANSLATION_RECEIPT.as_posix()}: committed Sail "
            "translation receipt is not canonical pretty JSON"
        )
    digest = codec.sha256_file(receipt_path)
    if artifacts.get(COMMITTED_TRANSLATION_RECEIPT.as_posix()) != digest:
        raise RefinementError(
            f"{COMMITTED_TRANSLATION_RECEIPT.as_posix()}: translation receipt "
            "digest does not match the committed manifest"
        )
    return definitions, _verify_translation_receipt(receipt, definitions)


def _carried_monad_bridge(
    paths: Paths,
    manifest: dict[str, object],
    generated_backend_sha256: str,
) -> dict[str, object]:
    """Validate the committed cross-project Lean proof receipt."""
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RefinementError(
            "committed manifest has no generated artifact digest map"
        )
    receipt_path = paths.formal / COMMITTED_MONAD_BRIDGE_RECEIPT
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RefinementError(
            f"{COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()}: committed "
            "generated Sail monad bridge receipt is absent"
        )
    receipt = codec.load_json(receipt_path)
    if receipt_path.read_bytes() != codec.pretty_bytes(receipt):
        raise RefinementError(
            f"{COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()}: committed "
            "generated Sail monad bridge receipt is not canonical pretty JSON"
        )
    digest = codec.sha256_file(receipt_path)
    if artifacts.get(COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()) != digest:
        raise RefinementError(
            f"{COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()}: monad bridge "
            "receipt digest does not match the committed manifest"
        )
    return sail_lean_bridge.validate_carried(
        paths,
        receipt,
        generated_backend_sha256,
    )


def _render_capsule(evidence: SailEvidence) -> bytes:
    from . import render  # deferred: render imports this module at load time

    definitions = evidence.translation_receipt["definitions"]
    return (
        render.SAIL_LEAN_TEMPLATE.replace(
            "__UTYPE_DIGEST__",
            evidence.definition_hashes["execute_UTYPE"],
        )
        .replace(
            "__ITYPE_DIGEST__",
            evidence.definition_hashes["execute_ITYPE"],
        )
        .replace(
            "__RTYPE_DIGEST__",
            evidence.definition_hashes["execute_RTYPE"],
        )
        .replace(
            "__TRANSLATION_RECEIPT_DIGEST__",
            str(evidence.translation_receipt["canonical_digest"]),
        )
        .replace(
            "__UTYPE_AST_DIGEST__",
            str(definitions["execute_UTYPE"]["ast_sha256"]),
        )
        .replace(
            "__ITYPE_AST_DIGEST__",
            str(definitions["execute_ITYPE"]["ast_sha256"]),
        )
        .replace(
            "__RTYPE_AST_DIGEST__",
            str(definitions["execute_RTYPE"]["ast_sha256"]),
        )
        .encode("utf-8")
    )


def _refuse_minting_sail_artifacts(paths: Paths, evidence: SailEvidence) -> None:
    """Reused evidence may reproduce the Sail artifacts and nothing else."""
    rendered_artifacts = {
        COMMITTED_CONFIGURATION: evidence.exact_configuration,
        COMMITTED_CAPSULE: _render_capsule(evidence),
        COMMITTED_TRANSLATION_RECEIPT:
            codec.pretty_bytes(evidence.translation_receipt),
        COMMITTED_MONAD_BRIDGE_RECEIPT:
            codec.pretty_bytes(evidence.monad_bridge_receipt),
        **{
            relative: evidence.definition_slices[name].encode("utf-8")
            for name, relative in COMMITTED_DEFINITIONS.items()
        },
    }
    for relative, rendered in rendered_artifacts.items():
        path = paths.formal / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"{relative.as_posix()}: committed Sail artifact is absent; "
                "reused evidence can only reproduce existing Sail output"
            )
        if path.read_bytes() != rendered:
            raise RefinementError(
                f"{relative.as_posix()}: reusing the committed Sail evidence "
                "would rewrite this artifact; only the live Sail toolchain may "
                "mint new Sail output"
            )


def capture_pinned_generated_evidence(
    paths: Paths,
    generated_file: Path,
) -> SailEvidence:
    """Capture slices from the exact backend already bound by the manifest.

    This is a narrow bootstrap for adding translation artifacts to an older
    committed manifest. It does not run Sail and therefore remains carried
    evidence: the supplied backend must be byte-identical to the backend digest
    previously minted by a live pinned-toolchain run.
    """
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("kind") != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError(
            "committed refinement manifest identity is invalid; exact backend "
            "slices cannot be captured"
        )
    carried = manifest.get("sail")
    if not isinstance(carried, dict):
        raise RefinementError(
            "committed refinement manifest has no Sail provenance block"
        )
    _carried_base_pins(carried)
    if (
        carried.get("normalization") not in {
            LEGACY_NORMALIZATION,
            NORMALIZATION,
        }
        or not isinstance(
            carried.get("generated_monad_normalization_theorem"),
            bool,
        )
    ):
        raise RefinementError(
            "committed Sail normalization boundary is not eligible for "
            "translation-artifact capture"
        )
    profile_file_sha256 = _carried_inputs(paths, carried)
    _profile(paths.root)
    configuration = _carried_configuration(paths, manifest, carried)
    generated = generated_file.resolve()
    if generated_file.is_symlink() or not generated.is_file():
        raise RefinementError(
            "translation capture requires a regular generated backend file"
        )
    expected_backend_digest = _carried_digest(
        carried,
        "generated_backend_file_sha256",
    )
    actual_backend_digest = codec.sha256_file(generated)
    if actual_backend_digest != expected_backend_digest:
        raise RefinementError(
            "supplied generated Sail backend does not match the backend "
            f"already bound by the committed manifest "
            f"({actual_backend_digest} != {expected_backend_digest})"
        )
    try:
        generated_text = generated.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RefinementError(
            "supplied generated Sail backend is unreadable"
        ) from exc
    definitions = {
        name: _extract_definition(generated_text, name)
        for name in GENERATED_DEFINITION_HASHES
    }
    definition_hashes = {
        name: codec.sha256_bytes(text.encode("utf-8"))
        for name, text in definitions.items()
    }
    if definition_hashes != GENERATED_DEFINITION_HASHES:
        raise RefinementError(
            "supplied backend definitions do not match the pinned hashes"
        )
    _validate_semantic_shapes(definitions)
    translation_receipt = _translation_receipt(definitions)
    monad_bridge_receipt = sail_lean_bridge.verify(
        paths,
        generated,
        actual_backend_digest,
    )
    return SailEvidence(
        source_root=None,
        compiler=None,
        compiler_sha256=None,
        simulator_sha256=None,
        generated_file=generated,
        generated_file_sha256=actual_backend_digest,
        source_file_sha256=_carried_digest(carried, "source_file_sha256"),
        model_entry_sha256=_carried_digest(carried, "model_entry_sha256"),
        base_configuration_sha256=_carried_digest(
            carried,
            "base_configuration_sha256",
        ),
        exact_configuration=configuration,
        exact_configuration_sha256=codec.sha256_bytes(configuration),
        profile_file_sha256=profile_file_sha256,
        checkout_state=str(carried["checkout_state"]),
        definition_hashes=definition_hashes,
        definition_slices=definitions,
        source_slice_hashes=dict(SOURCE_SLICE_HASHES),
        translation_receipt=translation_receipt,
        monad_bridge_receipt=monad_bridge_receipt,
        evidence_source=CARRIED_EVIDENCE,
    )


def carried_evidence(paths: Paths) -> SailEvidence:
    """Rebuild the Sail evidence from committed provenance, never from a tool.

    Nothing here can invent Sail output. Every field is either pinned in this
    module, re-hashed from a file in this repository, or copied verbatim out of
    the committed manifest and then required to round-trip back to it; and
    every Sail artifact must already exist with exactly the reproduced bytes.
    The result is labelled `carried-committed-sail-evidence` in the manifest and
    is refused by `toolchain`, so no release receipt can rest on it.
    """
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("kind") != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError(
            "committed refinement manifest identity is invalid; its Sail "
            "provenance cannot be reused"
        )
    carried = manifest.get("sail")
    if not isinstance(carried, dict):
        raise RefinementError(
            "committed refinement manifest has no Sail provenance block"
        )
    _carried_pins(carried)
    profile_file_sha256 = _carried_inputs(paths, carried)
    _profile(paths.root)
    configuration = _carried_configuration(paths, manifest, carried)
    definitions, translation_receipt = _carried_translation(paths, manifest)
    generated_backend_sha256 = _carried_digest(
        carried,
        "generated_backend_file_sha256",
    )
    monad_bridge_receipt = _carried_monad_bridge(
        paths,
        manifest,
        generated_backend_sha256,
    )
    evidence = SailEvidence(
        source_root=None,
        compiler=None,
        compiler_sha256=None,
        simulator_sha256=None,
        generated_file=None,
        generated_file_sha256=generated_backend_sha256,
        source_file_sha256=_carried_digest(carried, "source_file_sha256"),
        model_entry_sha256=_carried_digest(carried, "model_entry_sha256"),
        base_configuration_sha256=_carried_digest(
            carried,
            "base_configuration_sha256",
        ),
        exact_configuration=configuration,
        exact_configuration_sha256=codec.sha256_bytes(configuration),
        profile_file_sha256=profile_file_sha256,
        checkout_state=str(carried["checkout_state"]),
        definition_hashes=dict(GENERATED_DEFINITION_HASHES),
        definition_slices=definitions,
        source_slice_hashes=dict(SOURCE_SLICE_HASHES),
        translation_receipt=translation_receipt,
        monad_bridge_receipt=monad_bridge_receipt,
        evidence_source=CARRIED_EVIDENCE,
    )
    reconstructed = provenance(evidence)
    reconstructed.pop("evidence_source")
    if reconstructed != {
        key: value for key, value in carried.items() if key != "evidence_source"
    }:
        raise RefinementError(
            "reused Sail evidence does not reproduce the committed provenance "
            "block; re-derive it with the live Sail toolchain"
        )
    _refuse_minting_sail_artifacts(paths, evidence)
    return evidence


def provenance(evidence: SailEvidence) -> dict[str, object]:
    return {
        "repository": SAIL_REPOSITORY,
        "revision": SAIL_REVISION,
        "checkout_state": evidence.checkout_state,
        "compiler_version": SAIL_VERSION,
        "architectural_profile": "rv32im-zkvm-v1",
        "profile_file_sha256": evidence.profile_file_sha256,
        "model_entry": MODEL_ENTRY.as_posix(),
        "model_entry_sha256": evidence.model_entry_sha256,
        "base_configuration": BASE_CONFIGURATION.as_posix(),
        "base_configuration_sha256": evidence.base_configuration_sha256,
        "exact_configuration": EXACT_CONFIGURATION.as_posix(),
        "exact_configuration_sha256": evidence.exact_configuration_sha256,
        "validated_isa_string": "rv32im",
        "source_file": SOURCE_FILE.as_posix(),
        "source_file_sha256": evidence.source_file_sha256,
        "generated_backend_file": GENERATED_FILE.as_posix(),
        "generated_backend_file_sha256": evidence.generated_file_sha256,
        "generated_definition_sha256": evidence.definition_hashes,
        "source_slice_sha256": evidence.source_slice_hashes,
        "normalization": NORMALIZATION,
        "generated_ast_translation_receipt": {
            "artifact": COMMITTED_TRANSLATION_RECEIPT.as_posix(),
            "schema_version": sail_translation.SCHEMA_VERSION,
            "parser_version": sail_translation.PARSER_VERSION,
            "canonical_digest":
                evidence.translation_receipt["canonical_digest"],
            "definition_ast_sha256": {
                name: evidence.translation_receipt["definitions"][name][
                    "ast_sha256"
                ]
                for name in sorted(GENERATED_DEFINITION_HASHES)
            },
        },
        "generated_monad_bridge_receipt": {
            "artifact": COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix(),
            "schema_version": sail_lean_bridge.SCHEMA_VERSION,
            "canonical_digest":
                evidence.monad_bridge_receipt["canonical_digest"],
            "theorems": evidence.monad_bridge_receipt["theorems"],
            "claim_boundary":
                evidence.monad_bridge_receipt["claim_boundary"],
        },
        "generated_monad_normalization_theorem": True,
        "generated_step_loop_framing_theorem": False,
        "evidence_source": evidence.evidence_source,
    }


def toolchain(evidence: SailEvidence) -> dict[str, object]:
    """Platform-local binaries recorded in the receipt, not portable inputs."""
    if evidence.evidence_source != LIVE_EVIDENCE:
        raise RefinementError(
            "the semantic toolchain record requires live Sail evidence; "
            f"{evidence.evidence_source} carries no compiler or simulator digest"
        )
    return {
        "compiler": {
            "version": SAIL_VERSION,
            "sha256": evidence.compiler_sha256,
        },
        "simulator": {
            "sha256": evidence.simulator_sha256,
        },
    }
