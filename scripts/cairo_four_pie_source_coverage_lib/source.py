from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .identity import (
    NAME_RE,
    SEMANTIC_REGISTRY_PATH,
    CoverageError,
    exact_keys,
    git_output,
    load_json,
    sha256_path,
)


CLAIM_FIELD_RE = re.compile(
    r"^\s*pub ([a-z][a-z0-9_]*):\s*Option<[a-z][a-z0-9_]*::ClaimGenerator>",
    re.MULTILINE,
)
CENSUS_ROW_RE = re.compile(
    r"^  ([a-z][a-z0-9_]*)\s+cols=(\d+)\s+lookup_words=(\d+)\s+sub_words=(\d+)"
)
CENSUS_SKIP_RE = re.compile(r"^  ([a-z][a-z0-9_]*)\s+")


def parse_census(text: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    count_patterns = {
        "files_scanned": r"^Files scanned:\s+(\d+)$",
        "with_write_trace_simd": r"^\s+with write_trace_simd:\s+(\d+)$",
        "rewritable": r"^\s+MATCHED \(rewritable\):\s+(\d+)$",
        "trait_extension": r"^\s+MATCHED \(needs trait ext: u32/input\):\s+(\d+)$",
        "skipped": r"^\s+skipped:\s+(\d+)$",
    }
    summary: dict[str, int] = {}
    for key, pattern in count_patterns.items():
        match = re.search(pattern, text, re.MULTILINE)
        if not match:
            raise CoverageError(f"census missing summary field {key}")
        summary[key] = int(match.group(1))

    status: str | None = None
    entries: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if line == "--- MATCHED files (rewritable now) ---":
            status = "rewritable"
            continue
        if line.startswith("--- MATCHED files (needs trait extension:"):
            status = "trait_extension"
            continue
        if line == "--- SKIPPED files (loud reasons) ---":
            status = "skipped"
            continue
        if line.startswith("--- "):
            status = None
            continue
        if status in {"rewritable", "trait_extension"}:
            match = CENSUS_ROW_RE.match(line)
            if match:
                name, columns, lookup, sub = match.groups()
                if name in entries:
                    raise CoverageError(f"census repeats component {name}")
                entries[name] = {
                    "status": status,
                    "trace_columns": int(columns),
                    "lookup_words": int(lookup),
                    "sub_input_words": int(sub),
                }
        elif status == "skipped":
            match = CENSUS_SKIP_RE.match(line)
            if match:
                name = match.group(1)
                if name in entries:
                    raise CoverageError(f"census repeats component {name}")
                entries[name] = {
                    "status": "skipped",
                    "source_writer_present": "no `fn write_trace_simd`" not in line,
                }
    if len(entries) != summary["files_scanned"]:
        raise CoverageError(
            f"census parsed {len(entries)} entries, expected {summary['files_scanned']}"
        )
    return summary, entries


def authenticate_source(
    source_root: Path, manifest: dict[str, Any], census_path: Path
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    exact_keys(
        manifest,
        {
            "authority_sha256",
            "format",
            "provenance",
            "registry_sha256",
            "source",
            "toolchain",
            "version",
        },
        "source semantic manifest",
    )
    if manifest["provenance"] != "source-derived":
        raise CoverageError("source semantic manifest provenance is not source-derived")
    source = manifest["source"]
    toolchain = manifest["toolchain"]
    if not isinstance(source, dict) or not isinstance(toolchain, dict):
        raise CoverageError("source semantic manifest source/toolchain must be objects")
    exact_keys(
        source,
        {"repository", "revision", "stwo_revision", "tree"},
        "source semantic manifest source",
    )
    exact_keys(
        toolchain,
        {
            "cargo",
            "generator_cargo_lock_sha256",
            "generator_sha256",
            "rustc",
            "rustfmt",
            "source_cargo_lock_sha256",
        },
        "source semantic manifest toolchain",
    )
    revision = git_output(source_root, "rev-parse", "HEAD")
    tree = git_output(source_root, "rev-parse", "HEAD^{tree}")
    if revision != source["revision"] or tree != source["tree"]:
        raise CoverageError(
            f"stwo-cairo source mismatch: expected {source['revision']}:{source['tree']}, "
            f"got {revision}:{tree}"
        )
    if git_output(source_root, "status", "--porcelain"):
        raise CoverageError("pinned stwo-cairo source worktree is dirty")
    generator = source_root / "tools/witness_genericize/src/main.rs"
    cargo_lock = source_root / "Cargo.lock"
    if sha256_path(generator) != toolchain["generator_sha256"]:
        raise CoverageError("witness census generator hash differs from manifest")
    if sha256_path(cargo_lock) != toolchain["source_cargo_lock_sha256"]:
        raise CoverageError("stwo-cairo Cargo.lock hash differs from manifest")

    census_text = census_path.read_text(encoding="utf-8")
    summary, census = parse_census(census_text)
    components_dir = source_root / "crates/prover/src/witness/components"
    source_files = {
        path.stem: path
        for path in components_dir.glob("*.rs")
        if path.name != "mod.rs"
    }
    if set(source_files) != set(census):
        raise CoverageError(
            "source component registry differs from census: "
            f"source_only={sorted(set(source_files) - set(census))}, "
            f"census_only={sorted(set(census) - set(source_files))}"
        )
    claims_path = source_root / "crates/prover/src/witness/cairo_claim_generator.rs"
    claims = set(CLAIM_FIELD_RE.findall(claims_path.read_text(encoding="utf-8")))
    if claims != set(source_files):
        raise CoverageError(
            "source ClaimGenerator differs from component registry: "
            f"claims_only={sorted(claims - set(source_files))}, "
            f"files_only={sorted(set(source_files) - claims)}"
        )
    for name, path in source_files.items():
        census[name]["source_sha256"] = sha256_path(path)
        actual_writer = "fn write_trace_simd" in path.read_text(
            encoding="utf-8", errors="strict"
        )
        stated_writer = census[name].get("source_writer_present", True)
        if actual_writer != stated_writer:
            raise CoverageError(f"{name} writer presence differs from census")
        census[name]["source_writer_present"] = actual_writer
    return (
        {
            "repository": source["repository"],
            "revision": revision,
            "tree": tree,
            "stwo_revision": source["stwo_revision"],
            "component_count": len(source_files),
            "census": {
                **summary,
                "bytes": census_path.stat().st_size,
                "sha256": sha256_path(census_path),
            },
        },
        census,
    )


def load_semantic_registry(
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    registry = load_json(SEMANTIC_REGISTRY_PATH)
    exact_keys(registry, {"components", "format", "version"}, "semantic registry")
    digest = sha256_path(SEMANTIC_REGISTRY_PATH)
    if digest != manifest["registry_sha256"]:
        raise CoverageError(
            f"semantic registry hash mismatch: expected {manifest['registry_sha256']}, "
            f"got {digest}"
        )
    entries: dict[str, dict[str, Any]] = {}
    for component in registry["components"]:
        name = component.get("name") if isinstance(component, dict) else None
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name in entries:
            raise CoverageError(f"semantic registry has invalid component: {name!r}")
        entries[name] = component
    return (
        {
            "format": registry["format"],
            "version": registry["version"],
            "bytes": SEMANTIC_REGISTRY_PATH.stat().st_size,
            "sha256": digest,
            "registered_components": sorted(entries),
        },
        entries,
    )
