#!/usr/bin/env python3
"""Ratchet source ownership and layout rules from CONTRIBUTING.md.

Inventory scope:

* Zig, Metal, Objective-C, and C headers under ``src/``;
* the root ``build.zig`` and Zig/Python support under ``build/`` or
  ``build_support/``;
* maintained Python under ``scripts/``; and
* Rust sources under repository-owned ``tools/`` crates.

Generated, vendored, cache, and build-output directories are excluded. Repository-
local Zig, Metal, Python, build, Cargo, and Rust module edges are resolved where
their syntax is static. External package imports and dynamically constructed build
paths remain outside this source-layout check.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts.source_conformance_lib import build_graph, owners, python_graph, rust_graph
    from scripts.source_conformance_lib.model import Finding
except ModuleNotFoundError:  # Direct execution adds scripts/, not the repository root.
    from source_conformance_lib import build_graph, owners, python_graph, rust_graph
    from source_conformance_lib.model import Finding


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "conformance/source-baseline.json"
BASELINE_VERSION = 3
BASELINE_TRACKS = ("active_native_backend", "deferred_todo")
DEFAULT_BASELINE_TRACK = "active_native_backend"
IMPORT_RE = re.compile(r'@import\("([^"\n]+)"\)')
MSL_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"\n]+)"', re.MULTILINE)
MSL_INCLUDE_PREFIX = "stwo_zig/"
SRC_SOURCE_SUFFIXES = frozenset({".zig", ".metal", ".m", ".h"})
BUILD_SUPPORT_SUFFIXES = frozenset({".zig", ".py"})
EXCLUDED_DIRECTORY_NAMES = frozenset({
    ".cache",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".zig-cache",
    "__pycache__",
    "generated",
    "target",
    "vendor",
    "zig-out",
})
MANUAL_SOURCE_CEILING = 850
OWNER_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ROOT_ALLOWLIST = frozenset({
    "cairo_cuda.zig",
    "metal_arena_plan_cli.zig",
    "riscv_bench_cli.zig",
    "riscv_metal_bench_cli.zig",
    "riscv_trace_cli.zig",
    "std_shims_freestanding.zig",
    "stwo.zig",
    "stwo_aggregate_cpu.zig",
    "stwo_aggregate_metal.zig",
    "stwo_cairo_cpu.zig",
    "stwo_deep.zig",
    "stwo_native_cpu.zig",
    "stwo_native_metal.zig",
    "stwo_riscv_cpu.zig",
    "tests.zig",
})
FORBIDDEN_TARGETS = {
    "core": frozenset({"backend", "backends", "prover", "frontends", "integrations", "examples", "bench", "tools"}),
    "backend": frozenset({"backends", "frontends", "integrations", "examples", "tools"}),
    "prover": frozenset({"backends", "frontends", "integrations", "examples", "tools"}),
    "backends": frozenset({"frontends", "integrations", "examples", "tools"}),
    "frontends": frozenset({"backends", "integrations", "tools"}),
}


@dataclass(frozen=True, order=True)
class OwnedSource:
    path: Path
    display_path: Path
    category: str


def iter_tree_sources(root: Path, suffixes: frozenset[str]) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and not EXCLUDED_DIRECTORY_NAMES.intersection(path.relative_to(root).parts[:-1])
    )


def inventory(repo: Path) -> list[OwnedSource]:
    """Return the explicit, repository-owned manual-source inventory."""
    sources: list[OwnedSource] = []
    src_root = repo / "src"
    for path in iter_tree_sources(src_root, SRC_SOURCE_SUFFIXES):
        sources.append(OwnedSource(path, path.relative_to(src_root), "src"))

    build_file = repo / "build.zig"
    if build_file.is_file():
        sources.append(OwnedSource(build_file, Path("build.zig"), "build"))
    for directory in ("build", "build_support"):
        root = repo / directory
        for path in iter_tree_sources(root, BUILD_SUPPORT_SUFFIXES):
            sources.append(OwnedSource(path, path.relative_to(repo), "build"))

    scripts_root = repo / "scripts"
    for path in iter_tree_sources(scripts_root, frozenset({".py"})):
        sources.append(OwnedSource(path, path.relative_to(repo), "python"))

    tools_root = repo / "tools"
    for path in iter_tree_sources(tools_root, frozenset({".rs"})):
        sources.append(OwnedSource(path, path.relative_to(repo), "rust-tool"))
    return sorted(set(sources))


def relative_import(source: Path, imported: str, src_root: Path) -> Path | None:
    if not imported.endswith(".zig") or not imported.startswith("."):
        return None
    resolved = (source.parent / imported).resolve()
    try:
        return resolved.relative_to(src_root.resolve())
    except ValueError:
        return None


def is_generated(text: str) -> bool:
    header = "\n".join(text.splitlines()[:8]).lower()
    return (
        "generated" in header
        and "generator:" in header
        and "regenerate:" in header
    )


def scan(repo: Path) -> list[Finding]:
    src_root = repo / "src"
    shader_include_root = src_root / "backends/metal/shaders/include"
    findings: list[Finding] = []
    for owned_source in inventory(repo):
        source = owned_source.path
        relative = owned_source.display_path
        text = source.read_text(encoding="utf-8")
        line_count = len(text.splitlines())
        if line_count > MANUAL_SOURCE_CEILING and not is_generated(text):
            findings.append(Finding(
                f"file-size:{relative.as_posix()}",
                f"{relative}: {line_count} lines exceeds the {MANUAL_SOURCE_CEILING}-line manual-source ceiling",
                line_count,
            ))

        if owned_source.category == "src" and source.suffix == ".metal":
            for imported in MSL_INCLUDE_RE.findall(text):
                if not imported.startswith(MSL_INCLUDE_PREFIX):
                    findings.append(Finding(
                        f"shader-include:{relative.as_posix()}->{imported}",
                        f'{relative}: repository shader includes must use "{MSL_INCLUDE_PREFIX}..." ({imported})',
                    ))
                    continue
                target = (shader_include_root / imported[len(MSL_INCLUDE_PREFIX):]).resolve()
                try:
                    target.relative_to(shader_include_root.resolve())
                except ValueError:
                    findings.append(Finding(
                        f"shader-include:{relative.as_posix()}->{imported}",
                        f"{relative}: shader include escapes the declared include root ({imported})",
                    ))
                    continue
                if not target.is_file():
                    findings.append(Finding(
                        f"shader-include:{relative.as_posix()}->{imported}",
                        f"{relative}: shader include is not a declared repository header ({imported})",
                    ))
            continue

        if (
            owned_source.category == "src"
            and len(relative.parts) == 1
            and relative.name not in ROOT_ALLOWLIST
        ):
            findings.append(Finding(
                f"root-source:{relative.name}",
                f"{relative}: executable, test, or implementation source belongs in a responsibility directory",
            ))

        if owned_source.category != "src" or source.suffix != ".zig":
            continue
        findings.extend(owners.scan_zig(relative, text))
        source_layer = relative.parts[0] if len(relative.parts) > 1 else None
        forbidden = FORBIDDEN_TARGETS.get(source_layer, frozenset())
        if not forbidden:
            continue
        for imported in IMPORT_RE.findall(text):
            target = relative_import(source, imported, src_root)
            if target is None or len(target.parts) < 2:
                continue
            target_layer = target.parts[0]
            if target_layer in forbidden:
                findings.append(Finding(
                    f"dependency:{relative.as_posix()}->{target.as_posix()}",
                    f"{relative}: {source_layer} must not import {target_layer} ({imported})",
                ))
    findings.extend(python_graph.scan(repo))
    findings.extend(build_graph.scan(repo))
    findings.extend(rust_graph.scan(repo))
    findings.extend(owners.scan(repo))
    return sorted(set(findings))


def load_baseline(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "findings"}
        or payload.get("version") != BASELINE_VERSION
        or not isinstance(payload.get("findings"), list)
    ):
        raise ValueError(f"invalid source conformance baseline: {path}")
    result: dict[str, dict[str, object]] = {}
    for entry in payload["findings"]:
        if not isinstance(entry, dict):
            raise ValueError(f"invalid baseline finding in {path}")
        allowed_fields = {
            "key",
            "owner",
            "reason",
            "next_extraction",
            "plan",
            "track",
            "max_lines",
        }
        if not set(entry).issubset(allowed_fields):
            raise ValueError(f"baseline finding has unknown fields in {path}")
        key = entry.get("key")
        owner = entry.get("owner")
        reason = entry.get("reason")
        plan = entry.get("plan")
        track = entry.get("track")
        next_extraction = entry.get("next_extraction")
        if not isinstance(key, str) or not key:
            raise ValueError(f"invalid baseline finding in {path}")
        if not isinstance(owner, str) or OWNER_RE.fullmatch(owner) is None:
            raise ValueError(f"baseline finding lacks a valid owner: {key}")
        if track not in BASELINE_TRACKS:
            raise ValueError(f"baseline finding lacks a valid track: {key}")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or not isinstance(plan, str)
            or not plan.strip()
            or not isinstance(next_extraction, str)
            or not next_extraction.strip()
        ):
            raise ValueError(f"baseline finding lacks reason/plan/next_extraction: {key}")
        if key.startswith("file-size:"):
            max_lines = entry.get("max_lines")
            if not isinstance(max_lines, int) or isinstance(max_lines, bool) or max_lines <= MANUAL_SOURCE_CEILING:
                raise ValueError(f"file-size baseline finding lacks a valid max_lines budget: {key}")
        elif "max_lines" in entry:
            raise ValueError(f"non-file-size baseline finding has max_lines: {key}")
        if key in result:
            raise ValueError(f"duplicate baseline finding: {key}")
        result[key] = entry
    return result


def write_baseline(
    path: Path,
    findings: list[Finding],
    track: str = DEFAULT_BASELINE_TRACK,
) -> None:
    if track not in BASELINE_TRACKS:
        raise ValueError(f"invalid source conformance baseline track: {track}")

    def entry_for(finding: Finding) -> dict[str, object]:
        entry: dict[str, object] = {
            "key": finding.key,
            "owner": "source-conformance",
            "track": track,
            "reason": "Legacy source-layout debt present when the conformance ratchet was introduced.",
            "next_extraction": "Classify and extract the next responsibility named by the remediation plan.",
            "plan": (
                "conformance/decomposition-plan.md"
                if ".metal" in finding.key
                else "conformance/decomposition-plan.md"
            ),
        }
        if finding.key.startswith("file-size:"):
            entry["max_lines"] = finding.line_count or MANUAL_SOURCE_CEILING + 1
        return entry

    payload = {
        "version": BASELINE_VERSION,
        "findings": [entry_for(finding) for finding in findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--update-baseline", action="store_true")
    strict_group = parser.add_mutually_exclusive_group()
    strict_group.add_argument(
        "--strict",
        action="store_true",
        help="reject baseline findings from every track as well as new findings",
    )
    strict_group.add_argument(
        "--strict-track",
        choices=BASELINE_TRACKS,
        help=(
            "reject baseline findings assigned to one track; optimization-readiness command: "
            "python3 scripts/check_source_conformance.py --strict-track active_native_backend"
        ),
    )
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    baseline_path = args.baseline if args.baseline.is_absolute() else repo / args.baseline
    findings = scan(repo)
    if args.update_baseline:
        write_baseline(baseline_path, findings)
        try:
            display_path = baseline_path.relative_to(repo)
        except ValueError:
            display_path = baseline_path
        print(f"wrote {len(findings)} findings to {display_path}")
        return 0

    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 2

    current = {finding.key: finding for finding in findings}
    new_keys = sorted(current.keys() - baseline.keys())
    stale_keys = sorted(baseline.keys() - current.keys())
    grown_keys = sorted(
        key
        for key in current.keys() & baseline.keys()
        if current[key].line_count is not None
        and current[key].line_count > baseline[key].get("max_lines", MANUAL_SOURCE_CEILING)
    )
    invalid_plan_keys: list[str] = []
    for key, entry in baseline.items():
        plan = Path(entry["plan"])
        if plan.is_absolute():
            invalid_plan_keys.append(key)
            continue
        resolved_plan = (repo / plan).resolve()
        try:
            resolved_plan.relative_to(repo)
        except ValueError:
            invalid_plan_keys.append(key)
            continue
        if not resolved_plan.is_file():
            invalid_plan_keys.append(key)

    for key in new_keys:
        print(f"error: {current[key].message}", file=sys.stderr)
    for key in stale_keys:
        print(f"error: stale baseline entry must be removed: {key}", file=sys.stderr)
    for key in grown_keys:
        print(
            f"error: {current[key].message}; baseline budget is {baseline[key]['max_lines']} lines",
            file=sys.stderr,
        )
    for key in invalid_plan_keys:
        print(f"error: baseline decomposition plan is missing or outside the repository: {key}", file=sys.stderr)

    strict_keys = (
        set(current)
        if args.strict
        else {
            key
            for key in current.keys() & baseline.keys()
            if baseline[key]["track"] == args.strict_track
        }
        if args.strict_track is not None
        else set()
    )
    if strict_keys:
        for finding in findings:
            if finding.key in strict_keys and finding.key not in new_keys:
                print(f"error: {finding.message}", file=sys.stderr)
        if args.strict_track is not None:
            print(
                f"error: strict source track {args.strict_track} contains "
                f"{len(strict_keys)} finding(s)",
                file=sys.stderr,
            )
        return 1
    if new_keys or stale_keys or grown_keys or invalid_plan_keys:
        return 1
    track_counts = {
        track: sum(
            1
            for key in current.keys() & baseline.keys()
            if baseline[key]["track"] == track
        )
        for track in BASELINE_TRACKS
    }
    counts = ", ".join(f"{track_counts[track]} {track}" for track in BASELINE_TRACKS)
    print(
        f"source conformance: {len(findings)} explained legacy findings "
        f"({counts}), no new violations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
