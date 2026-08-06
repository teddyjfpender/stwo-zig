"""Keep experimental typed-AIR proposal authority out of production code."""

from __future__ import annotations

import re
from pathlib import Path

from . import comments
from .common import iter_tree_sources
from .model import Finding


# These identifiers name the H-009 cost model, search, canonical proposal
# artifact, or its checked projections. Strings are scanned as well as ordinary
# identifiers so reflective access and direct file imports cannot evade the
# boundary merely by spelling a name inside a literal.
PROPOSAL_REFERENCE_RE = re.compile(
    r"\b(?:"
    r"cost_aware_materializer|"
    r"materialization_(?:cost(?:_direct)?|cut_set|fixed_direct|"
    r"frontier(?:_[a-z0-9_]+)?|neighbourhood)|"
    r"typed_poseidon2_(?:fixed_direct|frontier_artifact)|"
    r"h009_poseidon2_frontier(?:_[a-z0-9_]+)?|"
    r"typed_air_h009_artifacts"
    r")\b"
)

LANG_ROOT = Path("frontends/riscv/air/lang")
AUTHORING_FILES = frozenset({
    "cost_aware_materializer.zig",
    "cost_aware_materializer_adversarial_test.zig",
    "cost_aware_materializer_test.zig",
    "materialization_cost.zig",
    "materialization_cost_direct.zig",
    "materialization_cost_direct_test.zig",
    "materialization_cost_test.zig",
    "materialization_cut_set.zig",
    "materialization_cut_set_test.zig",
    "materialization_fixed_cost_test.zig",
    "materialization_fixed_direct.zig",
    "materialization_fixed_direct_test.zig",
    "materialization_frontier_command.zig",
    "materialization_frontier_cost_model.zig",
    "materialization_frontier_cost_model_test.zig",
    "materialization_frontier_digest.zig",
    "materialization_frontier_manifest.zig",
    "materialization_frontier_manifest_lengths.zig",
    "materialization_frontier_manifest_test.zig",
    "materialization_frontier_manifest_test_support.zig",
    "materialization_frontier_manifest_validate.zig",
    "materialization_frontier_manifest_wire.zig",
    "materialization_frontier_projection.zig",
    "materialization_frontier_projection_test.zig",
    "materialization_frontier_retention.zig",
    "materialization_neighbourhood.zig",
    "materialization_neighbourhood_test.zig",
    "typed_poseidon2_fixed_direct.zig",
    "typed_poseidon2_frontier_artifact.zig",
    "typed_poseidon2_frontier_artifact_test.zig",
})
EXPLICIT_NON_AUTHORITY_CONSUMERS = frozenset({
    Path("frontends/riscv/build.zig"),
    Path("frontends/riscv/materialization_frontier_tool.zig"),
    Path("frontends/riscv/test_inventory.zig"),
})
ARTIFACT_TEST = LANG_ROOT / "typed_poseidon2_frontier_artifact_test.zig"
ARTIFACT_MODULE_CONSUMERS = frozenset({
    Path("frontends/riscv/build.zig"),
    ARTIFACT_TEST,
})


def scan(repo: Path) -> list[Finding]:
    """Reject in-repository production references to H-009 proposal names."""
    findings: list[Finding] = []
    src_root = repo / "src"
    for source in iter_tree_sources(src_root, frozenset({".zig"})):
        relative = source.relative_to(src_root)
        text = comments.strip_zig(source.read_text(encoding="utf-8"))
        references = sorted(set(PROPOSAL_REFERENCE_RE.findall(text)))
        unexpected = [
            reference
            for reference in references
            if not _reference_is_allowed(relative, reference)
        ]
        if not unexpected:
            continue
        display = relative.as_posix()
        findings.append(Finding(
            f"typed-air-proposal-consumer:{display}",
            f"{display}: H-009 proposal authority is tool/test-only; "
            f"unexpected production reference(s): {', '.join(unexpected)}",
        ))
    return findings


def _reference_is_allowed(relative: Path, reference: str) -> bool:
    if reference == "typed_air_h009_artifacts":
        return relative in ARTIFACT_MODULE_CONSUMERS
    if reference.startswith("h009_poseidon2_frontier"):
        return relative == ARTIFACT_TEST
    return _is_non_authority_source(relative)


def _is_non_authority_source(relative: Path) -> bool:
    if relative in EXPLICIT_NON_AUTHORITY_CONSUMERS:
        return True
    try:
        name = relative.relative_to(LANG_ROOT).name
    except ValueError:
        return False
    return name in AUTHORING_FILES
