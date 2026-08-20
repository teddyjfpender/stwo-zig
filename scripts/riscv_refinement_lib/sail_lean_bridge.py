"""Kernel-check opcode publication bindings against generated Sail Lean."""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import air_program_contract, codec
from .model import LEAN_TOOLCHAIN, Paths, RefinementError

SCHEMA_VERSION = "stwo-generated-sail-monad-bridge-v1"
BRIDGE_DIRECTORY = Path("formal/riscv-refinement/generated-sail-bridge")
PILOT_SOURCE = BRIDGE_DIRECTORY / "Pilot.lean"
COMPOSITION_SOURCE = BRIDGE_DIRECTORY / "Composition.lean"
PUBLICATION_SOURCE = BRIDGE_DIRECTORY / "Publication.lean"
# Keep the exact 47-source kernel-build closure in topological dependency
# order. Every source is compiled to the same temporary olean directory; the
# bounded scheduler admits a module only after its local imports are complete,
# while independent proof branches may use separate Lean processes.
BRIDGE_SOURCES = tuple(
    BRIDGE_DIRECTORY / name
    for name in (
        "Pilot.lean",
        "Composition.lean",
        "ExecutionClosure.lean",
        "ExecutionCompare.lean",
        "DecodeAluBase.lean",
        "DecodeAluBaseState.lean",
        "DecodeAluIType.lean",
        "DecodeAluShift.lean",
        "DecodeAluSlli.lean",
        "DecodeAluSrli.lean",
        "DecodeAluSrai.lean",
        "DecodeAluShiftCertificates.lean",
        "DecodeMulDivEncoding.lean",
        "DecodeMulDivState.lean",
        "DecodeMulDivGate.lean",
        "DecodeMulDivMul.lean",
        "DecodeMulDivMulh.lean",
        "DecodeMulDivMulhsu.lean",
        "DecodeMulDivMulhu.lean",
        "DecodeMulDivDiv.lean",
        "DecodeMulDivDivu.lean",
        "DecodeMulDivRem.lean",
        "DecodeMulDivRemu.lean",
        "DecodeMulDiv.lean",
        "MulDivArithmetic.lean",
        "DecodeControl.lean",
        "DecodeControlState.lean",
        "ExecutionControl.lean",
        "ExecutionControlBranches.lean",
        "ExecutionControlJump.lean",
        "DecodeMemory.lean",
        "DecodeMemoryState.lean",
        "ExecutionMemory.lean",
        "ExecutionMemoryWrite.lean",
        "ExecutionMemoryVmem.lean",
        "ExecutionMemoryStore.lean",
        "PublicationAlu.lean",
        "PublicationCompare.lean",
        "PublicationShifts.lean",
        "PublicationControl.lean",
        "PublicationMemory.lean",
        "PublicationMemoryTheorem.lean",
        "PublicationMulDivMultiply.lean",
        "PublicationMulDivHighMultiply.lean",
        "PublicationMulDivDivision.lean",
        "PublicationMulDiv.lean",
        "Publication.lean",
    )
)
# The publication module is the public cross-project axiom-print entrypoint.
# Keep the singular alias for callers that intentionally mutate that entrypoint.
BRIDGE_SOURCE = PUBLICATION_SOURCE
BRIDGE_BUILD_MAX_JOBS = 4
SUPPORT_PATCH = Path("conformance/riscv/sail-lean-riscv-extras.patch")
COMMITTED_RECEIPT = Path(
    "generated/sail/generated-monad-bridge-receipt-v1.json"
)
LEAN_SAIL_REVISION = "79b4d08505af29d88b3918f32d29840fae1fa191"
SUPPORT_PATCH_SHA256 = (
    "ceb85e86b94a9f254502373f821198f9dfd3019105b77dc7987818b2a4388070"
)
PATCHED_SUPPORT_SHA256 = (
    "7d774a62134bd79b6a0bebd85ce2f215a2a3ce3552e74d4e3c9ac4c9ed24e95c"
)
GENERATED_MODULE_SHA256 = {
    "LeanRV32IM/Callbacks.lean":
        "08dbceb93ab1e5711e51f28127c6999b9d15331a13ac6317a4a096bc22d6e194",
    "LeanRV32IM/Defs.lean":
        "48049c73d2445dc9e84526b797ea31217082a54239d7a9f59e680dd303170b09",
    "LeanRV32IM/InstsBegin.lean":
        "e7dfdc19a7be526cffdd27e4eb63289a5b8640135f30164a98fd56a127e8d7d8",
    "LeanRV32IM/InstsEnd.lean":
        "074d61135954f165c3490630aec286f28638ba99f1c64c92056bd3c29c05c21a",
    "LeanRV32IM/PcAccess.lean":
        "5664b05b4d12ec41a9928adaf5767ebfe34b8e4bd103ed2d64764294812c727d",
    "LeanRV32IM/Regs.lean":
        "0ef72eb67e9628999a3e738394cbdd7915381006cb807ab16121fe0695230af5",
    "LeanRV32IM/RiscvExtras.lean": PATCHED_SUPPORT_SHA256,
}

# Exact generated execute-definition identities used by the 46 admitted
# selectors.  Several selectors share one generated match definition; each
# publication entry still repeats the exact digest in manifest order so no
# selector can inherit evidence from an unordered family set.
GENERATED_EXECUTE_DEFINITION_SHA256 = {
    "execute_BTYPE":
        "a11b2b09e968914dca9357daca2cd8a35cf4ad5c1928f3a10d7c32f4276a3a2a",
    "execute_DIV":
        "d0f4f08b121c59f548139820078411a66f8174c852250df5e397dbfbfa400070",
    "execute_FENCE":
        "693dd10a1ab20451cfda389c750d6c6c822812674d1b606df153a9d8fa43b606",
    "execute_ITYPE":
        "1d014d14c56ab01dc511fc36c8c6ee4dea56a63708257b8a5df451e7c6f6b17d",
    "execute_JAL":
        "b8059df92609bcabb2390263f871c3f268c7412c339c387dcf5ffe61e7224b35",
    "execute_JALR":
        "de8be00415e4df2f499f850f3e8e694235aa4bc6552aeebc5781598c10e345e3",
    "execute_LOAD":
        "df0a2a6920158599f9088a245c670c7a160fe45bb7c1bbf165b6299aa0daf363",
    "execute_MUL":
        "05dfb7ec7ba8011b1dd5f594ea59ceea1137edc4af32379d3561cc1e4e216b82",
    "execute_REM":
        "93a012c6781b6a6c2091610b10361b0a503c810c361d269f43cd173f2887501a",
    "execute_RTYPE":
        "01359d58d0543ce431b7315caf9961ea80329de2f017f2ea6cb205a7149cd628",
    "execute_SHIFTIOP":
        "00c8d03dfb9e5ee7af2fa689b2f2fc9960406deb2c17bbcc4a5167374bca2e57",
    "execute_STORE":
        "825282d41c18828a70302942d1a33192b7de4811d2f03202e8e625e3faf396f4",
    "execute_UTYPE":
        "f746995b8c903140529bb742379c295bee8d95a02de2d730990dc77fe1cacf1c",
}


def _selector_execute_definition(mnemonic: str, family: str) -> str:
    if family in {"base_alu_reg", "lt_reg", "shifts_reg"}:
        return "execute_RTYPE"
    if family in {"base_alu_imm", "lt_imm"}:
        return "execute_ITYPE"
    if family == "shifts_imm":
        return "execute_SHIFTIOP"
    if family == "load_store":
        return "execute_LOAD" if mnemonic.startswith("l") else "execute_STORE"
    if family in {"branch_eq", "branch_lt"}:
        return "execute_BTYPE"
    if family in {"lui", "auipc"}:
        return "execute_UTYPE"
    if family in {"mul", "mulh"}:
        return "execute_MUL"
    if family == "div":
        return "execute_DIV" if mnemonic.startswith("div") else "execute_REM"
    if family in {"jal", "jalr", "fence"}:
        return f"execute_{mnemonic.upper()}"
    raise RefinementError(
        f"no generated execute definition for {mnemonic}/{family}"
    )


SELECTOR_SOURCE_DEFINITIONS = {
    mnemonic.upper(): _selector_execute_definition(mnemonic, family)
    for _, mnemonic, family in air_program_contract.OPCODES
}
SELECTOR_SOURCE_DIGESTS = [
    {
        "selector": mnemonic.upper(),
        "sha256": GENERATED_EXECUTE_DEFINITION_SHA256[
            SELECTOR_SOURCE_DEFINITIONS[mnemonic.upper()]
        ],
    }
    for _, mnemonic, _ in air_program_contract.OPCODES
]
ADMITTED_SELECTORS = [
    mnemonic.upper()
    for _, mnemonic, _ in air_program_contract.OPCODES
]
NORMALIZED_THEOREMS = tuple(
    f"LeanRV32IM.Functions.complete_{selector}_normalizes"
    for selector in ADMITTED_SELECTORS
)
PUBLICATION_THEOREMS = tuple(
    f"LeanRV32IM.Publication.{selector}_accepted_air_refines"
    for selector in ADMITTED_SELECTORS
)
FULL_STEP_THEOREM = (
    "LeanRV32IM.Functions.generated_full_step_retirement_composition"
)
UNIVERSAL_PUBLICATION_THEOREM = (
    "LeanRV32IM.Publication.universal_publication_contract"
)
THEOREMS = (
    *NORMALIZED_THEOREMS,
    *PUBLICATION_THEOREMS,
    FULL_STEP_THEOREM,
    UNIVERSAL_PUBLICATION_THEOREM,
)
KERNEL_AXIOMS = frozenset(
    {
        "propext",
        "Classical.choice",
        "Quot.sound",
    }
)
PINNED_GENERATED_MODEL_AXIOMS = frozenset(
    {
        # Exact syntactic extern closure of the pinned generated full step.
        # The generated RV32IM decoder still contains disabled extension arms,
        # so Lean's dependency audit retains their support constants even when
        # a selector-specific profile proves those arms unreachable.  These
        # names are assumptions of the pinned generated model, not new bridge
        # assumptions, and their defining source digest is receipt-bound.
        "cancel_reservation",
        "get_16_random_bits",
        "load_reservation",
        "match_reservation",
        "plat_term_write",
        "riscv_f16Add",
        "riscv_f16Div",
        "riscv_f16Eq",
        "riscv_f16Le",
        "riscv_f16Le_quiet",
        "riscv_f16Lt",
        "riscv_f16Lt_quiet",
        "riscv_f16Mul",
        "riscv_f16MulAdd",
        "riscv_f16Sqrt",
        "riscv_f16Sub",
        "riscv_f16ToF32",
        "riscv_f16ToF64",
        "riscv_f16ToI32",
        "riscv_f16ToUi32",
        "riscv_f16roundToInt",
        "riscv_f32Add",
        "riscv_f32Div",
        "riscv_f32Eq",
        "riscv_f32Le",
        "riscv_f32Le_quiet",
        "riscv_f32Lt",
        "riscv_f32Lt_quiet",
        "riscv_f32Mul",
        "riscv_f32MulAdd",
        "riscv_f32Sqrt",
        "riscv_f32Sub",
        "riscv_f32ToBF16",
        "riscv_f32ToF16",
        "riscv_f32ToF64",
        "riscv_f32ToI32",
        "riscv_f32ToI64",
        "riscv_f32ToUi32",
        "riscv_f32ToUi64",
        "riscv_f32roundToInt",
        "riscv_f64Add",
        "riscv_f64Div",
        "riscv_f64Eq",
        "riscv_f64Le",
        "riscv_f64Le_quiet",
        "riscv_f64Lt",
        "riscv_f64Lt_quiet",
        "riscv_f64Mul",
        "riscv_f64MulAdd",
        "riscv_f64Sqrt",
        "riscv_f64Sub",
        "riscv_f64ToF16",
        "riscv_f64ToF32",
        "riscv_f64ToI32",
        "riscv_f64ToI64",
        "riscv_f64ToUi32",
        "riscv_f64ToUi64",
        "riscv_f64roundToInt",
        "riscv_i32ToF16",
        "riscv_i32ToF32",
        "riscv_i32ToF64",
        "riscv_i64ToF32",
        "riscv_i64ToF64",
        "riscv_ui32ToF16",
        "riscv_ui32ToF32",
        "riscv_ui32ToF64",
        "riscv_ui64ToF32",
        "riscv_ui64ToF64",
        "sys_enable_experimental_extensions",
        "valid_reservation",
    }
)
APPROVED_AXIOMS = KERNEL_AXIOMS | PINNED_GENERATED_MODEL_AXIOMS
_CONTROL_FLOW_SELECTORS = frozenset(
    {"BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU", "JAL", "JALR"}
)
_LOAD_SELECTORS = frozenset({"LB", "LH", "LW", "LBU", "LHU"})
_STORE_SELECTORS = frozenset({"SB", "SH", "SW"})


def _selector_theorem_axioms(selector: str) -> frozenset[str]:
    if selector in _LOAD_SELECTORS:
        return frozenset(
            {
                "load_reservation",
                "plat_term_write",
                "sys_enable_experimental_extensions",
            }
        )
    if selector in _STORE_SELECTORS:
        return frozenset(
            {
                "match_reservation",
                "plat_term_write",
                "sys_enable_experimental_extensions",
            }
        )
    if selector in _CONTROL_FLOW_SELECTORS:
        return frozenset({"sys_enable_experimental_extensions"})
    return frozenset()


_NORMALIZER_MODEL_AXIOMS = {
    f"LeanRV32IM.Functions.complete_{selector}_normalizes":
        _selector_theorem_axioms(selector)
    for selector in ADMITTED_SELECTORS
}
_PUBLICATION_MODEL_AXIOMS = {
    # Every public proposition retains the exact generated full-step frame and
    # successful trace decoder, so its syntactic closure is deliberately the
    # same pinned extern set as the standalone full-step theorem.
    f"LeanRV32IM.Publication.{selector}_accepted_air_refines":
        PINNED_GENERATED_MODEL_AXIOMS
    for selector in ADMITTED_SELECTORS
}
EXPECTED_THEOREM_AXIOMS = {
    theorem: sorted(
        KERNEL_AXIOMS
        | (
            PINNED_GENERATED_MODEL_AXIOMS
            if theorem in {
                FULL_STEP_THEOREM,
                UNIVERSAL_PUBLICATION_THEOREM,
            }
            else _NORMALIZER_MODEL_AXIOMS.get(theorem, frozenset())
                | _PUBLICATION_MODEL_AXIOMS.get(theorem, frozenset())
        )
    )
    for theorem in THEOREMS
}
CLAIM_BOUNDARY = {
    "generated_execute_clause_monad_normalization": True,
    "generated_execute_clause_input_binding": True,
    "input_bound_selectors": list(ADMITTED_SELECTORS),
    "normalized_retirement_selectors": list(ADMITTED_SELECTORS),
    "generated_retirement_composition": True,
    "pinned_generated_model_axioms": sorted(
        PINNED_GENERATED_MODEL_AXIOMS
    ),
    "sequential_next_pc_and_tick_fragment": True,
    "fetch_interrupt_trap_and_step_loop_framing": True,
    # Every public opcode result now constructs a successful row-local
    # generated decoder/execute retirement from its component bindings.
    "constructive_row_local_execution": True,
    "publication_binding": True,
}
_UNPATCHED_OPEN = b"open LeanRV32IM.Defs\n\n"
_AXIOM_LINE = re.compile(
    r"^'([^']+)' depends on axioms: \[([^\]]*)\]$",
    re.MULTILINE,
)
_PROOF_ESCAPES = re.compile(
    r"\b(?:sorry|admit|axiom|native_decide)\b"
)


def _run(
    argv: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
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
            if len(detail) > 8000:
                detail = "... " + detail[-8000:]
        raise RefinementError(
            "generated Sail Lean bridge command failed: "
            + " ".join(argv)
            + (f": {detail}" if detail else "")
        ) from exc
    return completed.stdout.strip()


def _project(generated_file: Path) -> Path:
    generated = generated_file.resolve()
    project = generated.parent.parent
    if (
        generated.name != "InstsEnd.lean"
        or generated.parent.name != "LeanRV32IM"
        or not (project / "lakefile.toml").is_file()
        or not (project / "lean-toolchain").is_file()
    ):
        raise RefinementError(
            "generated Sail backend is not inside a Lean_RV32IM project"
        )
    return project


def _bridge_lean_command(
    paths: Paths,
    source_relative: Path,
    output: Path | None = None,
) -> list[str]:
    """Build a Lean 4.29-safe command for an external bridge source."""
    source = paths.root / source_relative
    command = [
        "lake",
        "env",
        "lean",
        "--tstack=400000",
        "-R",
        str(source.parent),
    ]
    if output is not None:
        command.extend(["-o", str(output)])
    command.append(str(source))
    return command


def _bridge_source_dependencies(paths: Paths) -> dict[Path, tuple[Path, ...]]:
    """Recover and validate the declared bridge's local import DAG."""
    by_module = {source.stem: source for source in BRIDGE_SOURCES}
    if len(by_module) != len(BRIDGE_SOURCES):
        raise RefinementError("generated Sail bridge has duplicate module names")
    order = {source: index for index, source in enumerate(BRIDGE_SOURCES)}
    dependencies: dict[Path, tuple[Path, ...]] = {}
    for source in BRIDGE_SOURCES:
        path = paths.root / source
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise RefinementError(
                f"generated Sail bridge source is unreadable: {source}"
            ) from exc
        imported: set[Path] = set()
        for raw_line in lines:
            line = raw_line.strip()
            if line.startswith("public import "):
                modules = line.removeprefix("public import ").split()
            elif line.startswith("import "):
                modules = line.removeprefix("import ").split()
            else:
                continue
            imported.update(
                by_module[module]
                for module in modules
                if module in by_module
            )
        local = tuple(
            candidate for candidate in BRIDGE_SOURCES if candidate in imported
        )
        forward = [
            dependency
            for dependency in local
            if order[dependency] >= order[source]
        ]
        if forward:
            raise RefinementError(
                f"generated Sail bridge source {source} imports a module "
                "outside the reviewed dependency order: "
                + ", ".join(dependency.as_posix() for dependency in forward)
            )
        dependencies[source] = local
    return dependencies


def _bridge_build_jobs(source_count: int) -> int:
    if source_count <= 0:
        raise RefinementError("generated Sail bridge closure is empty")
    logical_cpus = max(1, os.cpu_count() or 1)
    # Lean itself can use more than one logical CPU. Reserve two logical CPUs
    # per process before applying the hard memory/concurrency ceiling.
    cpu_budget = max(1, (logical_cpus + 1) // 2)
    return min(BRIDGE_BUILD_MAX_JOBS, cpu_budget, source_count)


def _kernel_build_bridge_sources(
    paths: Paths,
    project: Path,
    environment: dict[str, str],
    output_dir: Path,
) -> str:
    """Kernel-build the ordered external bridge closure one module at a time."""
    bridge_environment = dict(environment)
    inherited_lean_path = bridge_environment.get("LEAN_PATH")
    bridge_environment["LEAN_PATH"] = (
        str(output_dir)
        if not inherited_lean_path
        else f"{output_dir}{os.pathsep}{inherited_lean_path}"
    )
    dependencies = _bridge_source_dependencies(paths)
    order = {source: index for index, source in enumerate(BRIDGE_SOURCES)}
    outputs: dict[Path, str] = {}
    completed: set[Path] = set()
    pending = set(BRIDGE_SOURCES)
    running: dict[concurrent.futures.Future[str], Path] = {}
    max_workers = _bridge_build_jobs(len(BRIDGE_SOURCES))

    def compile_source(source: Path) -> str:
        output = output_dir / source.with_suffix(".olean").name
        return _run(
            _bridge_lean_command(paths, source, output),
            project,
            env=bridge_environment,
            timeout=600,
        )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="sail-lean-bridge",
    ) as executor:
        while pending or running:
            available = max_workers - len(running)
            ready = [
                source
                for source in BRIDGE_SOURCES
                if source in pending
                and all(
                    dependency in completed
                    for dependency in dependencies[source]
                )
            ]
            for source in ready[:available]:
                pending.remove(source)
                running[executor.submit(compile_source, source)] = source
            if not running:
                raise RefinementError(
                    "generated Sail bridge dependency graph cannot make progress"
                )
            finished, _ = concurrent.futures.wait(
                running,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in sorted(finished, key=lambda item: order[running[item]]):
                source = running.pop(future)
                outputs[source] = future.result()
                completed.add(source)
    return "\n".join(
        outputs[source]
        for source in BRIDGE_SOURCES
        if outputs[source]
    )


def _patch_support(paths: Paths, project: Path) -> None:
    patch = paths.root / SUPPORT_PATCH
    if (
        patch.is_symlink()
        or not patch.is_file()
        or codec.sha256_file(patch) != SUPPORT_PATCH_SHA256
    ):
        raise RefinementError(
            "generated Sail Lean support patch identity drifted"
        )
    support = project / "LeanRV32IM" / "RiscvExtras.lean"
    if support.is_symlink() or not support.is_file():
        raise RefinementError(
            "generated Sail project has no regular RiscvExtras.lean"
        )
    data = support.read_bytes()
    if _UNPATCHED_OPEN in data:
        if data.count(_UNPATCHED_OPEN) != 1:
            raise RefinementError(
                "generated RiscvExtras namespace patch anchor is ambiguous"
            )
        codec.atomic_write(support, data.replace(_UNPATCHED_OPEN, b""))
    if codec.sha256_file(support) != PATCHED_SUPPORT_SHA256:
        raise RefinementError(
            "generated RiscvExtras differs beyond the pinned namespace fix"
        )


def _lean_sail_revision(project: Path) -> str:
    manifest = project / "lake-manifest.json"
    def read_matches() -> list[dict[str, object]]:
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            packages = payload["packages"]
            if not isinstance(packages, list):
                raise TypeError("packages is not a list")
            return [
                package
                for package in packages
                if isinstance(package, dict)
                and package.get("name") == "Sail"
            ]
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
        ) as exc:
            raise RefinementError(
                "generated Sail project dependency manifest is malformed"
            ) from exc

    if not manifest.is_file():
        _run(["lake", "update"], project, timeout=600)
    matches = read_matches()
    # Sail 0.20.2 may emit a syntactically valid bootstrap manifest with an
    # empty package list. Resolve the lakefile's exact `lean-sail` pin once,
    # then re-read and enforce the same singleton/revision checks below.
    if not matches:
        _run(["lake", "update"], project, timeout=600)
        matches = read_matches()
    try:
        revision = matches[0]["rev"]
    except (KeyError, IndexError) as exc:
        raise RefinementError(
            "generated Sail project dependency manifest is malformed"
        ) from exc
    if len(matches) != 1 or revision != LEAN_SAIL_REVISION:
        raise RefinementError(
            "generated Sail project resolved an unpinned lean-sail revision"
        )
    return revision


def _source_closure(project: Path) -> tuple[int, str]:
    from .sail_lean_evidence import source_closure

    return source_closure(project)


def _extract_definition(text: str, name: str) -> str:
    from .sail_lean_evidence import extract_definition

    return extract_definition(text, name)


def _validate_selector_source_digests(generated_file: Path) -> None:
    from .sail_lean_evidence import validate_selector_source_digests

    validate_selector_source_digests(generated_file)


def _proof_axioms(output: str) -> dict[str, list[str]]:
    from .sail_lean_evidence import proof_axioms

    return proof_axioms(output)

def _bridge_source_identities(paths: Paths) -> list[dict[str, str]]:
    """Scan and bind every source in the declared bridge closure."""
    identities: list[dict[str, str]] = []
    for relative in BRIDGE_SOURCES:
        source = paths.root / relative
        if source.is_symlink() or not source.is_file():
            raise RefinementError(
                f"generated Sail monad bridge source is absent: {relative}"
            )
        try:
            source_text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RefinementError(
                "generated Sail monad bridge source is unreadable: "
                f"{relative}"
            ) from exc
        stripped_comments = re.sub(
            r"/-!.*?-/", "", source_text, flags=re.DOTALL
        )
        if _PROOF_ESCAPES.search(stripped_comments):
            raise RefinementError(
                "generated Sail monad bridge contains a forbidden proof "
                f"escape: {relative}"
            )
        identities.append(
            {
                "path": relative.as_posix(),
                "sha256": codec.sha256_file(source),
            }
        )
    return identities


def _static_identity(
    paths: Paths,
    generated_backend_sha256: str,
) -> dict[str, Any]:
    source_identities = _bridge_source_identities(paths)
    bridge = paths.root / BRIDGE_SOURCE
    capsule = paths.formal / "RiscvRefinement/Sail/Generated/Pilot.lean"
    if capsule.is_symlink() or not capsule.is_file():
        raise RefinementError(
            "normalized generated Sail pilot capsule is absent"
        )
    return {
        "generated_backend_sha256": generated_backend_sha256,
        "bridge_source": BRIDGE_SOURCE.as_posix(),
        "bridge_source_sha256": codec.sha256_file(bridge),
        "bridge_sources": source_identities,
        "normalized_capsule":
            "RiscvRefinement/Sail/Generated/Pilot.lean",
        "normalized_capsule_sha256": codec.sha256_file(capsule),
        "support_patch": SUPPORT_PATCH.as_posix(),
        "support_patch_sha256": codec.sha256_file(
            paths.root / SUPPORT_PATCH
        ),
        "lean_toolchain": LEAN_TOOLCHAIN,
        "lean_sail_revision": LEAN_SAIL_REVISION,
        "generated_module_sha256": dict(GENERATED_MODULE_SHA256),
        "selector_source_digests": [
            dict(identity) for identity in SELECTOR_SOURCE_DIGESTS
        ],
        "theorems": list(THEOREMS),
        "claim_boundary": dict(CLAIM_BOUNDARY),
    }


def verify(
    paths: Paths,
    generated_file: Path,
    generated_backend_sha256: str,
) -> dict[str, Any]:
    """Build the exact generated project and kernel-check the cross bridge."""
    project = _project(generated_file)
    # Fail before provisioning/building the generated project if any member of
    # the handwritten bridge closure is absent or contains a proof escape.
    _bridge_source_identities(paths)
    if codec.sha256_file(generated_file) != generated_backend_sha256:
        raise RefinementError(
            "generated Sail bridge backend digest does not match its evidence"
        )
    _validate_selector_source_digests(generated_file)
    _patch_support(paths, project)
    revision = _lean_sail_revision(project)
    toolchain = (
        project / "lean-toolchain"
    ).read_text(encoding="utf-8").strip()
    if toolchain != LEAN_TOOLCHAIN:
        raise RefinementError(
            "generated Sail project Lean toolchain does not match the proof "
            "project"
        )
    source_count, source_digest = _source_closure(project)
    _run(["lake", "build", "LeanRV32IM"], project)
    _run(
        ["lake", "build", "RiscvRefinement.Sail.Generated.Pilot"],
        paths.formal,
        timeout=600,
    )
    environment = dict(os.environ)
    formal_lean_path = paths.formal / ".lake" / "build" / "lib" / "lean"
    inherited = environment.get("LEAN_PATH")
    environment["LEAN_PATH"] = (
        str(formal_lean_path)
        if not inherited
        else f"{formal_lean_path}{os.pathsep}{inherited}"
    )
    with tempfile.TemporaryDirectory(
        prefix="stwo-generated-sail-bridge-"
    ) as raw_output:
        output_dir = Path(raw_output)
        output = _kernel_build_bridge_sources(
            paths,
            project,
            environment,
            output_dir,
        )
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "stwo-generated-sail-monad-bridge",
        "evidence_source": "exact-pinned-generated-backend",
        **_static_identity(paths, generated_backend_sha256),
        "lean_sail_revision": revision,
        "generated_source_count": source_count,
        "generated_source_closure_sha256": source_digest,
        "theorem_axioms": _proof_axioms(output),
    }
    receipt["canonical_digest"] = codec.content_digest(receipt)
    return receipt


def validate_carried(
    paths: Paths,
    receipt: dict[str, Any],
    generated_backend_sha256: str,
) -> dict[str, Any]:
    """Validate the committed proof receipt without pretending to rebuild it."""
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("kind") != "stwo-generated-sail-monad-bridge"
        or receipt.get("evidence_source")
        != "exact-pinned-generated-backend"
        or receipt.get("canonical_digest") != codec.content_digest(receipt)
    ):
        raise RefinementError(
            "committed generated Sail monad bridge receipt identity is invalid"
        )
    static = _static_identity(paths, generated_backend_sha256)
    for key, expected in static.items():
        actual = receipt.get(key)
        if key == "theorems":
            if actual != expected:
                raise RefinementError(
                    "committed generated Sail bridge theorem list drifted"
                )
        elif actual != expected:
            raise RefinementError(
                f"committed generated Sail bridge field {key} drifted"
            )
    if (
        not isinstance(receipt.get("generated_source_count"), int)
        or receipt["generated_source_count"] <= 0
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt.get("generated_source_closure_sha256")),
        )
        is None
        or receipt.get("theorem_axioms")
        != EXPECTED_THEOREM_AXIOMS
    ):
        raise RefinementError(
            "committed generated Sail bridge proof inventory is invalid"
        )
    return receipt
