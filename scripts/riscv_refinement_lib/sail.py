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

from . import (
    codec,
    sail_backend as _sail_backend,
    sail_carried as _sail_carried,
    sail_contract as _sail_contract,
    sail_lean_bridge,
    sail_translation,
)
from .model import (
    SAIL_REPOSITORY,
    SAIL_REVISION,
    SAIL_VERSION,
    Paths,
    RefinementError,
)
from .sail_contract import (
    BASE_CONFIGURATION,
    CARRIED_EVIDENCE,
    CARRIED_INPUTS,
    COMMITTED_CAPSULE,
    COMMITTED_CONFIGURATION,
    COMMITTED_DEFINITIONS,
    COMMITTED_MONAD_BRIDGE_RECEIPT,
    COMMITTED_TRANSLATION_RECEIPT,
    EXACT_CONFIGURATION,
    GENERATED_DEFINITION_HASHES,
    GENERATED_FILE,
    LEGACY_NORMALIZATION,
    LIVE_EVIDENCE,
    MODEL_ENTRY,
    NORMALIZATION,
    OVERRIDE_PATHS,
    PATCHED_SOURCE,
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
    _merge_configuration,
    _profile,
    _relaxed_json,
    _run,
    _run_bytes,
    _strip_line_comments,
    _translation_receipt,
    _validate_semantic_shapes,
    _verify_translation_receipt,
    exact_configuration,
)
from .sail_backend import (
    _generated_file,
    _validate_exact_configuration,
    collect_evidence,
    discover_compiler,
    discover_source,
    prepare_exact_backend,
)
from .sail_carried import (
    _carried_base_pins,
    _carried_configuration,
    _carried_digest,
    _carried_inputs,
    _carried_monad_bridge,
    _carried_pins,
    _carried_translation,
    _refuse_minting_sail_artifacts,
    _render_capsule,
    capture_pinned_generated_evidence,
    carried_evidence,
    provenance,
    toolchain,
)

_SYNCED_BINDINGS = (
    "BASE_CONFIGURATION",
    "CARRIED_EVIDENCE",
    "CARRIED_INPUTS",
    "COMMITTED_CAPSULE",
    "COMMITTED_CONFIGURATION",
    "COMMITTED_DEFINITIONS",
    "COMMITTED_MONAD_BRIDGE_RECEIPT",
    "COMMITTED_TRANSLATION_RECEIPT",
    "EXACT_CONFIGURATION",
    "GENERATED_DEFINITION_HASHES",
    "GENERATED_FILE",
    "LEGACY_NORMALIZATION",
    "LIVE_EVIDENCE",
    "MODEL_ENTRY",
    "NORMALIZATION",
    "OVERRIDE_PATHS",
    "PATCHED_SOURCE",
    "PATCH_PATH",
    "PROFILE_PATH",
    "SAIL_REPOSITORY",
    "SAIL_REVISION",
    "SAIL_VERSION",
    "SIMULATOR",
    "SOURCE_FILE",
    "SOURCE_SLICE_HASHES",
)


def _sync_helper_bindings() -> None:
    """Propagate facade overrides before entering an implementation helper."""

    facade = globals()
    for helper in (_sail_contract, _sail_backend, _sail_carried):
        helper_globals = vars(helper)
        for name in _SYNCED_BINDINGS:
            if name in helper_globals:
                helper_globals[name] = facade[name]


def exact_configuration(repository_root: Path, source_root: Path) -> bytes:
    _sync_helper_bindings()
    return _sail_contract.exact_configuration(repository_root, source_root)


def prepare_exact_backend(
    repository_root: Path,
    source_root: Path | None,
    compiler: Path | None,
    force: bool,
) -> SailEvidence:
    _sync_helper_bindings()
    return _sail_backend.prepare_exact_backend(
        repository_root,
        source_root,
        compiler,
        force,
    )


def collect_evidence(
    repository_root: Path,
    source_root: Path | None,
    compiler: Path | None,
    generated_file: Path | None,
) -> SailEvidence:
    _sync_helper_bindings()
    return _sail_backend.collect_evidence(
        repository_root,
        source_root,
        compiler,
        generated_file,
    )


def capture_pinned_generated_evidence(
    paths: Paths,
    generated_file: Path,
) -> SailEvidence:
    _sync_helper_bindings()
    return _sail_carried.capture_pinned_generated_evidence(
        paths,
        generated_file,
    )


def carried_evidence(paths: Paths) -> SailEvidence:
    _sync_helper_bindings()
    return _sail_carried.carried_evidence(paths)


def provenance(evidence: SailEvidence) -> dict[str, object]:
    _sync_helper_bindings()
    return _sail_carried.provenance(evidence)


def toolchain(evidence: SailEvidence) -> dict[str, object]:
    _sync_helper_bindings()
    return _sail_carried.toolchain(evidence)
