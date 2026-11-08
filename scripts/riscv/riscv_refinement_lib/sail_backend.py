"""Live Sail toolchain discovery, preparation, and evidence collection."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from . import codec, sail_lean_bridge
from .model import Paths, RefinementError, SAIL_REVISION, SAIL_VERSION
from .sail_contract import (
    BASE_CONFIGURATION,
    EXACT_CONFIGURATION,
    GENERATED_DEFINITION_HASHES,
    GENERATED_FILE,
    LIVE_EVIDENCE,
    MODEL_ENTRY,
    OVERRIDE_PATHS,
    PATCH_PATH,
    PROFILE_PATH,
    SIMULATOR,
    SOURCE_FILE,
    SOURCE_SLICE_HASHES,
    SailEvidence,
    _checkout_state,
    _compiler_version,
    _extract_definition,
    _extract_source_slices,
    _git_revision,
    _profile,
    _run,
    _translation_receipt,
    _validate_semantic_shapes,
    exact_configuration,
)

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
