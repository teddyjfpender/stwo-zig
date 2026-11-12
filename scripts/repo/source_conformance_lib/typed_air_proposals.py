"""Keep experimental typed-AIR proposal authority out of production code."""

from __future__ import annotations

import re
from pathlib import Path

from . import comments
from .common import iter_tree_sources
from .model import Finding


# These identifiers name the H-009 cost model, search, canonical proposal
# artifact, its checked projections, or the H-010 proposal evaluator and
# benchmark. Strings are scanned as well as ordinary identifiers so reflective
# access and direct file imports cannot evade the boundary merely by spelling a
# name inside a literal.
PROPOSAL_REFERENCE_RE = re.compile(
    r"\b(?:"
    r"cost_aware_materializer|"
    r"materialization_(?:cost(?:_direct)?|cut_set|"
    r"direct_(?:program|benchmark)(?:_[a-z0-9_]+)?|"
    r"fixed_direct|frontier(?:_[a-z0-9_]+)?|neighbourhood)|"
    r"typed_poseidon2_(?:fixed_direct|frontier_artifact|"
    r"layout_executor(?:_[a-z0-9_]+)?)|"
    r"poseidon_layout_(?:benchmark|vector)(?:_[a-z0-9_]+)?|"
    r"h010(?:_|-)poseidon(?:_|-)layout(?:[_a-z0-9-]+)?|"
    r"h010_embedded|"
    r"h009_poseidon2_frontier(?:_[a-z0-9_]+)?|"
    r"typed_air_h009_artifacts|"
    r"typed_air_h010_artifacts"
    r")\b"
)

AUTHORING_PATHS = frozenset({
    Path("frontends/riscv/air/lang/materialization_frontier_command.zig"),
    Path("frontends/riscv/air_lang/cost_aware_materializer.zig"),
    Path("frontends/riscv/air_lang/materialization_cost.zig"),
    Path("frontends/riscv/air_lang/materialization_cut_set.zig"),
    Path("frontends/riscv/air_lang/materialization_direct_benchmark.zig"),
    Path("frontends/riscv/air_lang/materialization_frontier_digest.zig"),
    Path("frontends/riscv/air_lang/materialization_frontier_manifest_lengths.zig"),
    Path("frontends/riscv/air_lang/materialization_frontier_manifest_test_support.zig"),
    Path("frontends/riscv/air_lang/materialization_frontier_manifest_validate.zig"),
    Path("frontends/riscv/air_lang/materialization_frontier_manifest_wire.zig"),
    Path("frontends/riscv/air_lang/materialization_frontier_retention.zig"),
    Path("frontends/riscv/air_lang/materialization_neighbourhood.zig"),
    Path("frontends/riscv/air_lang/tests/cost_aware_materializer_adversarial_test.zig"),
    Path("frontends/riscv/air_lang/tests/materialization_cost_direct_test.zig"),
    Path("frontends/riscv/air_lang/tests/materialization_direct_benchmark_test.zig"),
    Path("frontends/riscv/memory/typed/materialization_frontier_cost_model.zig"),
    Path("frontends/riscv/memory/typed/materialization_frontier_manifest.zig"),
    Path("frontends/riscv/memory/typed/materialization_frontier_projection.zig"),
    Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_artifact.zig"),
    Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_command.zig"),
    Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_protocol.zig"),
    Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_rss.zig"),
    Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_vector.zig"),
    Path("frontends/riscv/memory/typed/tests/poseidon_layout_benchmark_artifact_test.zig"),
    Path("frontends/riscv/memory/typed/tests/poseidon_layout_benchmark_protocol_test.zig"),
    Path("frontends/riscv/memory/typed/tests/typed_poseidon2_frontier_artifact_test.zig"),
    Path("frontends/riscv/memory/typed/tests/typed_poseidon2_layout_executor_test.zig"),
    Path("frontends/riscv/memory/typed/typed_poseidon2_frontier_artifact.zig"),
    Path("frontends/riscv/memory/typed/typed_poseidon2_layout_executor.zig"),
    Path("frontends/riscv/memory/typed/typed_poseidon2_layout_executor_validate.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/cost_aware_materializer_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_cost_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_cut_set_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_direct_program_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_fixed_cost_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_fixed_direct_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_frontier_cost_model_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_frontier_manifest_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_frontier_projection_test.zig"),
    Path("frontends/riscv/testing/cases/air/lang/tests/materialization_neighbourhood_test.zig"),
})
EXPLICIT_NON_AUTHORITY_CONSUMERS = frozenset({
    Path("frontends/riscv/build.zig"),
    Path("frontends/riscv/compat/assembly/rv32/materialization_frontier_tool.zig"),
    Path("frontends/riscv/compat/assembly/rv32/poseidon_layout_benchmark_tool.zig"),
    Path("frontends/riscv/test_inventory.zig"),
    Path("frontends/riscv/testing/cases/polynomial_compiler_test_root.zig"),
    Path("frontends/riscv/air_lang/tests/root.zig"),
    Path("frontends/riscv/memory/tests/root.zig"),
    Path("frontends/riscv/rv32/tests/root.zig"),
    Path("frontends/riscv/testing/tests/root.zig"),
    Path("frontends/riscv/testing/focused_test_lookup_polynomial_v2_edit_0.zig"),
    Path("frontends/riscv/testing/focused_test_polynomial_compiler_0.zig"),
})
ARTIFACT_TEST = Path("frontends/riscv/memory/typed/tests/typed_poseidon2_frontier_artifact_test.zig")
LAYOUT_EXECUTOR_TEST = Path("frontends/riscv/memory/typed/tests/typed_poseidon2_layout_executor_test.zig")
BENCHMARK_COMMAND = Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_command.zig")
BENCHMARK_PROTOCOL = Path("frontends/riscv/memory/typed/poseidon_layout_benchmark_protocol.zig")
BENCHMARK_PROTOCOL_TEST = Path("frontends/riscv/memory/typed/tests/poseidon_layout_benchmark_protocol_test.zig")
BENCHMARK_ARTIFACT_TEST = Path("frontends/riscv/memory/typed/tests/poseidon_layout_benchmark_artifact_test.zig")
BENCHMARK_TOOL = Path("frontends/riscv/compat/assembly/rv32/poseidon_layout_benchmark_tool.zig")
ARTIFACT_DATA_CONSUMERS = frozenset({
    ARTIFACT_TEST,
    LAYOUT_EXECUTOR_TEST,
    BENCHMARK_COMMAND,
    BENCHMARK_PROTOCOL,
    BENCHMARK_PROTOCOL_TEST,
    BENCHMARK_TOOL,
})
ARTIFACT_MODULE_CONSUMERS = frozenset({
    Path("frontends/riscv/build.zig"),
    *ARTIFACT_DATA_CONSUMERS,
})
H010_ARTIFACT_MODULE_CONSUMERS = frozenset({
    Path("frontends/riscv/build.zig"),
    BENCHMARK_COMMAND,
    BENCHMARK_PROTOCOL_TEST,
    BENCHMARK_ARTIFACT_TEST,
    BENCHMARK_TOOL,
})


# The negative closure assertion also rejects familiar basenames in unrelated
# directories. Authorization itself is always by the exact path above.
AUTHORING_FILES = frozenset(path.name for path in AUTHORING_PATHS)
EXPORT_ROOTS = frozenset(Path("frontends/riscv") / owner / "mod.zig"
                         for owner in ("air_lang", "memory", "rv32", "testing"))


def without_testing_exports(text: str) -> str:
    """Mask only the explicit unstable namespace, preserving all other code."""
    match = re.search(r"\bpub\s+const\s+testing\s*=\s*struct\s*\{", text)
    if match is None:
        return text
    depth = 1
    index = match.end()
    while index < len(text) and depth:
        if text[index] == '"':
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    break
                index += 1
        elif text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    # An incomplete namespace is not a grant. Syntax qualification will also
    # reject it; the scanner must still report its proposal references.
    return text[:match.start()] + " " * (index - match.start()) + text[index:] if depth == 0 else text


def scan(repo: Path) -> list[Finding]:
    """Reject production references to H-009/H-010 proposal authority."""
    findings: list[Finding] = []
    src_root = repo / "src"
    for source in iter_tree_sources(src_root, frozenset({".zig"})):
        relative = source.relative_to(src_root)
        text = comments.strip_zig(source.read_text(encoding="utf-8"))
        if relative in EXPORT_ROOTS:
            text = without_testing_exports(text)
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
            f"{display}: H-009/H-010 proposal authority is tool/test-only; "
            f"unexpected production reference(s): {', '.join(unexpected)}",
        ))
    return findings


# The test-only embed bridges that define the artifact names live with the
# artifacts themselves (moved from design/typed-air/artifacts).
ARTIFACT_BRIDGES = frozenset({
    Path("frontends/riscv/air_lang/artifacts/h009_embedded.zig"),
    Path("frontends/riscv/air_lang/artifacts/h010_embedded.zig"),
})


def _reference_is_allowed(relative: Path, reference: str) -> bool:
    if relative in ARTIFACT_BRIDGES:
        return True
    if reference == "typed_air_h009_artifacts":
        return relative in ARTIFACT_MODULE_CONSUMERS
    if reference == "typed_air_h010_artifacts":
        return relative in H010_ARTIFACT_MODULE_CONSUMERS
    if reference.startswith("h009_poseidon2_frontier"):
        return relative in ARTIFACT_DATA_CONSUMERS
    return _is_non_authority_source(relative)


def _is_non_authority_source(relative: Path) -> bool:
    if relative in EXPLICIT_NON_AUTHORITY_CONSUMERS:
        return True
    # A familiar basename in a nested directory is not an authority grant.
    # Every authoring exception is one exact, reviewable path beneath the
    # language root, with test-only authoring files in its tests directory.
    return relative in AUTHORING_PATHS
