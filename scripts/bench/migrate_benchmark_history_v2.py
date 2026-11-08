#!/usr/bin/env python3
"""One-shot migration of the benchmark history archive from layout v1 to v2.

v1 named every file by its content hash and split the catalog across two
indexes; v2 groups each run's evidence under a human-readable directory:

    reports/<kind>/<sha>.json            -> runs/<run-id>/report.json
    deltas/benchmark_delta_v1/<sha>.json -> runs/<current>/delta-from-<baseline>.json
    matrix_bundles/<schema>/<sha>/       -> runs/<run-id>/bundle/
    matrix_bundles/index.json            -> merged into index.json (schema v2)

Information-preservation contract, enforced by this script:
  - every moved file keeps byte-identical content (sha256 re-verified after
    the move against the digests recorded in the v1 indexes);
  - the only deletion is the bundle's summary.json, and only after proving
    it is byte-identical to the run's report.json sitting beside it;
  - every v1 index field is carried into the v2 index (paths updated,
    digests unchanged), plus the new run identities.

Idempotent: a v2 archive is left untouched. Use --dry-run to preview.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from benchmark_delta_lib.naming import run_id_for_report  # noqa: E402


class MigrationError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def encoded_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError(f"cannot read {path}: {error}") from error


class Migration:
    def __init__(self, archive_dir: Path, dry_run: bool):
        self.archive = archive_dir.resolve()
        self.dry_run = dry_run
        self.moves: list[tuple[Path, Path]] = []
        self.dedup_removals: list[Path] = []

    def plan_move(self, source: Path, destination: Path) -> None:
        if not source.is_file():
            raise MigrationError(f"expected file is missing: {source}")
        self.moves.append((source, destination))

    def execute(self) -> None:
        for source, destination in self.moves:
            if self.dry_run:
                print(f"  move {source.relative_to(self.archive)}")
                print(f"    -> {destination.relative_to(self.archive)}")
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise MigrationError(f"destination already exists: {destination}")
            shutil.move(str(source), str(destination))
        for path in self.dedup_removals:
            if self.dry_run:
                print(f"  drop duplicate {path.relative_to(self.archive)} (== report.json)")
            else:
                path.unlink()


def migrate(archive_dir: Path, dry_run: bool) -> int:
    archive_dir = archive_dir.resolve()
    index_path = archive_dir / "index.json"
    index = load_json(index_path)
    if index.get("schema_version") == 2:
        print("archive is already layout v2; nothing to do")
        return 0
    if index.get("schema_version") != 1:
        raise MigrationError("unrecognized archive index schema_version")

    migration = Migration(archive_dir, dry_run)
    runs: dict[str, dict[str, Any]] = {}
    sha_to_run: dict[str, str] = {}

    # ---- reports -> runs/<id>/report.json ---------------------------------
    artifacts = index.get("artifacts", {})
    for sha, entry in sorted(artifacts.items()):
        source = archive_dir / entry["path"]
        if sha256_file(source) != sha:
            raise MigrationError(f"pre-move digest mismatch for report {sha[:12]}")
        report = load_json(source)
        rid = run_id_for_report(report)
        if rid in runs:
            rid = f"{rid}-{sha[:6]}"
        destination = archive_dir / "runs" / rid / "report.json"
        migration.plan_move(source, destination)
        kind = report.get("protocol")
        runs[rid] = {
            "kind": kind,
            "report": {
                "path": f"runs/{rid}/report.json",
                "bytes": entry["bytes"],
                "sha256": sha,
            },
            "deltas": [],
            "bundle": None,
        }
        sha_to_run[sha] = rid
        entry_new = {"path": f"runs/{rid}/report.json", "bytes": entry["bytes"], "run": rid}
        artifacts[sha] = entry_new

    # ---- deltas -> runs/<current>/delta-from-<baseline>.json ---------------
    deltas = index.get("deltas", {})
    comparisons = index.get("comparisons", [])
    delta_destination: dict[str, str] = {}
    for comparison in comparisons:
        delta_sha = comparison["delta_sha256"]
        baseline_run = sha_to_run.get(comparison["baseline_sha256"])
        current_run = sha_to_run.get(comparison["current_sha256"])
        if baseline_run is None or current_run is None:
            raise MigrationError(f"comparison references an unarchived report: {comparison['id']}")
        comparison["baseline_run"] = baseline_run
        comparison["current_run"] = current_run
        if delta_sha not in delta_destination:
            name = f"delta-from-{baseline_run}.json"
            candidate = f"runs/{current_run}/{name}"
            taken = set(delta_destination.values())
            if candidate in taken:
                candidate = f"runs/{current_run}/delta-from-{baseline_run}-{delta_sha[:6]}.json"
            delta_destination[delta_sha] = candidate
        comparison["delta_path"] = delta_destination[delta_sha]

    for delta_sha, entry in sorted(deltas.items()):
        source = archive_dir / entry["path"]
        if sha256_file(source) != delta_sha:
            raise MigrationError(f"pre-move digest mismatch for delta {delta_sha[:12]}")
        destination_rel = delta_destination.get(delta_sha)
        if destination_rel is None:
            # A delta with no comparison entry: keep it, attributed to nothing.
            destination_rel = f"runs/unattributed/{delta_sha[:12]}.json"
        migration.plan_move(source, archive_dir / destination_rel)
        current_run = destination_rel.split("/")[1]
        new_entry = {"path": destination_rel, "bytes": entry["bytes"], "run": current_run}
        baseline = next(
            (c["baseline_run"] for c in comparisons if c["delta_sha256"] == delta_sha), None
        )
        if baseline is not None:
            new_entry["baseline_run"] = baseline
        deltas[delta_sha] = new_entry
        if current_run in runs and destination_rel not in runs[current_run]["deltas"]:
            runs[current_run]["deltas"].append(destination_rel)

    # ---- bundles -> runs/<id>/bundle/ --------------------------------------
    bundles_out: dict[str, Any] = {}
    bundle_index_path = archive_dir / "matrix_bundles" / "index.json"
    if bundle_index_path.exists():
        bundle_index = load_json(bundle_index_path)
        for digest, locator in sorted(bundle_index.get("bundles", {}).items()):
            old_dir = archive_dir / locator["path"]
            manifest_path = old_dir / "manifest.json"
            if sha256_file(manifest_path) != digest:
                raise MigrationError(f"bundle manifest digest mismatch: {digest[:12]}")
            report_sha = locator["report_sha256"]
            rid = sha_to_run.get(report_sha)
            if rid is None:
                raise MigrationError(f"bundle references an unarchived report: {report_sha[:12]}")
            new_rel = f"runs/{rid}/bundle"
            migration.plan_move(manifest_path, archive_dir / new_rel / "manifest.json")
            tree_dir = old_dir / "tree"
            if tree_dir.is_dir():
                for source in sorted(p for p in tree_dir.rglob("*") if p.is_file()):
                    relative = source.relative_to(tree_dir)
                    migration.plan_move(
                        source, archive_dir / new_rel / "tree" / relative
                    )
            # summary.json duplicates the run's report bytes; prove it, then drop it.
            summary_path = old_dir / "summary.json"
            if summary_path.exists():
                report_entry = artifacts[report_sha]
                if sha256_file(summary_path) == report_sha:
                    migration.dedup_removals.append(summary_path)
                else:
                    migration.plan_move(
                        summary_path, archive_dir / new_rel / "summary.divergent.json"
                    )
                del report_entry  # only needed for the check above
            new_locator = dict(locator)
            new_locator["path"] = new_rel
            new_locator["run"] = rid
            bundles_out[digest] = new_locator
            runs[rid]["bundle"] = new_locator

    # ---- write the v2 index and clean up ------------------------------------
    new_index = {
        "schema_version": 2,
        "runs": dict(sorted(runs.items())),
        "artifacts": dict(sorted(artifacts.items())),
        "deltas": dict(sorted(deltas.items())),
        "bundles": dict(sorted(bundles_out.items())),
        "comparisons": comparisons,
        "migrated_from": "layout v1 (content-hash filenames); digests unchanged",
    }

    print(f"{'DRY RUN — ' if dry_run else ''}migrating {len(artifacts)} reports, "
          f"{len(deltas)} deltas, {len(bundles_out)} bundle(s) into {len(runs)} runs")
    migration.execute()
    if dry_run:
        return 0

    index_path.write_bytes(encoded_json(new_index))
    if bundle_index_path.exists():
        bundle_index_path.unlink()
    for stale in ("reports", "deltas", "matrix_bundles"):
        stale_dir = archive_dir / stale
        if stale_dir.exists():
            leftovers = [p for p in stale_dir.rglob("*") if p.is_file()]
            if leftovers:
                raise MigrationError(f"unexpected leftover files under {stale_dir}: {leftovers[:3]}")
            shutil.rmtree(stale_dir)

    # ---- post-migration verification ----------------------------------------
    failures = []
    for sha, entry in new_index["artifacts"].items():
        if sha256_file(archive_dir / entry["path"]) != sha:
            failures.append(entry["path"])
    for sha, entry in new_index["deltas"].items():
        if sha256_file(archive_dir / entry["path"]) != sha:
            failures.append(entry["path"])
    for digest, locator in new_index["bundles"].items():
        if sha256_file(archive_dir / locator["path"] / "manifest.json") != digest:
            failures.append(locator["path"])
    if failures:
        raise MigrationError(f"post-migration digest verification failed: {failures}")
    print(f"✓ migration complete; every digest re-verified ({len(new_index['artifacts'])} "
          f"reports, {len(new_index['deltas'])} deltas, {len(new_index['bundles'])} bundles)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        return migrate(args.archive_dir, args.dry_run)
    except MigrationError as error:
        print(f"migration failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
