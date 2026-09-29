#!/usr/bin/env python3
"""Run a pinned Cairo workload matrix serially, retaining failures and proof parity."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

if __package__:
    from . import benchmark_cairo as benchmark
else:
    import benchmark_cairo as benchmark

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "autoresearch/benchmarks/cairo/manifest.json"
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != "stwo-zig-cairo-suite-manifest-v1":
        raise ValueError("unsupported Cairo suite manifest")
    if manifest.get("security") != benchmark.CANONICAL_SECURITY:
        raise ValueError("suite security must be the canonical 70-query/26-bit configuration")
    workloads = manifest.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        raise ValueError("manifest requires workloads")
    names = set()
    for workload in workloads:
        name = workload.get("id", "")
        if not isinstance(name, str) or not SAFE_ID.fullmatch(name) or name in names:
            raise ValueError(f"invalid or duplicate workload ID: {name}")
        names.add(name)
        if workload.get("source") not in {"repository", "external-pie"}:
            raise ValueError(f"unknown workload source: {name}")
        if workload.get("kind") not in {"program", "prover-input"}:
            raise ValueError(f"unknown workload kind: {name}")
        if workload.get("tier") not in {"smoke", "canonical", "large"}:
            raise ValueError(f"unknown workload tier: {name}")
        if workload["kind"] == "program" and workload.get("program_type") not in {"json", "executable", "pie"}:
            raise ValueError(f"unknown program type: {name}")
        if workload["source"] == "external-pie" and (workload.get("program_type") != "pie" or Path(workload["path"]).name != workload["path"]):
            raise ValueError(f"external PIE must name one archive: {name}")
        if workload.get("arguments") and (workload["kind"] != "program" or workload.get("program_type") == "pie"):
            raise ValueError(f"arguments are invalid for this workload: {name}")
        for asset in [workload] + [workload[key] for key in ("arguments", "params") if key in workload]:
            if not isinstance(asset.get("path"), str) or not re.fullmatch(r"[0-9a-f]{64}", asset.get("sha256", "")):
                raise ValueError(f"invalid asset identity: {name}")
    return manifest


def resolve_assets(workload: dict, pie_dir: Path | None) -> dict[str, Path]:
    def checked(asset: dict, external: bool = False) -> Path:
        if external and pie_dir is None:
            raise FileNotFoundError("external PIE directory was not supplied (--pie-dir)")
        parent = pie_dir if external else ROOT
        path = (parent / asset["path"]).resolve()
        if not path.is_relative_to(parent.resolve()):
            raise ValueError(f"asset escapes its declared root: {asset['path']}")
        if not path.is_file():
            raise FileNotFoundError(f"missing workload asset: {path}")
        if benchmark.digest(path) != asset["sha256"]:
            raise ValueError(f"workload bytes differ from the pinned manifest: {path}")
        return path
    assets = {"input": checked(workload, workload["source"] == "external-pie")}
    for key in ("arguments", "params"):
        if key in workload:
            assets[key] = checked(workload[key])
    return assets


def summarize(records: list[dict]) -> list[dict]:
    rows = []
    for record in records:
        if record["status"] != "qualified":
            rows.append({key: record[key] for key in ("workload", "backend", "workers", "status", "error") if key in record})
            continue
        result = record["result"]
        summary = result.get("subsequent_trials_summary", result["summary"])
        rows.append({
            "workload": record["workload"], "backend": record["backend"], "workers": record["workers"],
            "status": "qualified", "process_seconds": summary["median_process_wall_ns"] / 1e9,
            "prove_seconds": summary["median_prove_ns"] / 1e9,
            "peak_rss_bytes": summary["peak_process_rss_bytes"],
            "peak_product_physical_footprint_bytes": summary.get("peak_product_physical_footprint_bytes"),
            "first_process_seconds": result["trials"][0]["process"]["wall_ns"] / 1e9,
            "aggregation": "subsequent-trial median" if len(result["trials"]) > 1 else "single trial",
            "proof_sha256": sorted({trial["proof_sha256"] for trial in result["trials"]}),
            "result_path": record["result_path"],
        })
    return rows


def qualify_parity(records: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for record in records:
        groups.setdefault((record["workload"], record["workers"]), []).append(record)
    evidence = []
    for (workload, workers), members in groups.items():
        if len(members) < 2:
            status = "single-backend"
        elif any(member["status"] != "qualified" for member in members):
            status = "incomplete"
        else:
            hashes = {trial["proof_sha256"] for member in members for trial in member["result"]["trials"]}
            status = "identical" if len(hashes) == 1 else "mismatch"
        evidence.append({"workload": workload, "workers": workers, "status": status})
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cpu", type=Path)
    parser.add_argument("--metal", type=Path)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--pie-dir", type=Path)
    parser.add_argument("--tier", choices=("smoke", "canonical", "large", "all"), default="smoke")
    parser.add_argument("--workload", action="append", help="Select named workloads instead of a tier; repeatable")
    parser.add_argument("--workers", nargs="+", type=int, help="Sweep explicit pool widths; default uses product detection")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--cache-mode", choices=("retained", "fresh-artifacts"), default="retained")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    products = {key: path.resolve() for key, path in (("cpu", args.cpu), ("metal", args.metal)) if path is not None}
    if not products:
        parser.error("at least one of --cpu or --metal is required")
    for path in list(products.values()) + [args.oracle]:
        if not path.is_file():
            parser.error(f"not a benchmark binary: {path}")
    if args.trials < 1 or args.trials > 100:
        parser.error("--trials must be between 1 and 100")
    workers = args.workers or [None]
    if len(set(workers)) != len(workers) or any(value is not None and not 1 <= value <= 32 for value in workers):
        parser.error("worker counts must be distinct integers between 1 and 32")
    manifest = load_manifest(args.manifest)
    selected = [workload for workload in manifest["workloads"] if
                (workload["id"] in args.workload if args.workload else args.tier == "all" or workload["tier"] == args.tier)]
    if args.workload and set(args.workload) - {workload["id"] for workload in selected}:
        parser.error("unknown workload ID")
    if not selected:
        parser.error("selection contains no workloads")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    suite = {
        "schema": "stwo-zig-cairo-benchmark-suite-v1", "status": "running",
        "host_details": benchmark.host_details(), "manifest_sha256": benchmark.digest(args.manifest),
        "security": manifest["security"], "cache_mode": args.cache_mode,
        "metal_pipeline_cache": "OS-managed and retained; admission time included in every process measurement",
        "scheduling": "one benchmark product process at a time, including all worker sweeps",
        "rss_scope": "largest process/descendant RSS, not sum of simultaneous allocations",
        "manifest_workload_count": len(manifest["workloads"]),
        "selection": [workload["id"] for workload in selected],
        "not_selected": [workload["id"] for workload in manifest["workloads"] if workload not in selected],
        "records": [],
    }
    for workload in selected:
        for count in workers:
            for backend in products:
                suite["records"].append({"workload": workload["id"], "family": workload["family"], "workers": count, "backend": backend, "status": "pending"})
    benchmark.write_result(args.out, suite)
    for record in suite["records"]:
        workload = next(workload for workload in selected if workload["id"] == record["workload"])
        folder = args.out / f"{record['workload']}-{record['backend']}-workers-{record['workers'] or 'auto'}"
        try:
            assets = resolve_assets(workload, args.pie_dir)
            env = dict(os.environ)
            if record["workers"] is not None:
                env["STWO_ZIG_WORKERS"] = str(record["workers"])
            if args.cache_mode == "fresh-artifacts":
                cache = args.out / "artifact-caches" / folder.name
                cache.mkdir(parents=True, exist_ok=False)
                env["STWO_CAIRO_PREPROCESSED_CACHE"] = "1"
                env["STWO_CAIRO_PREPROCESSED_CACHE_DIR"] = str(cache)
            request = argparse.Namespace(
                product=products[record["backend"]], oracle=args.oracle,
                program=assets["input"] if workload["kind"] == "program" else None,
                prover_input=assets["input"] if workload["kind"] == "prover-input" else None,
                program_type=workload.get("program_type"), arguments=assets.get("arguments"),
                params=assets.get("params"), trials=args.trials, out=folder,
            )
            record["status"] = "running"
            record["result_path"] = str(folder / "results.json")
            benchmark.write_result(args.out, suite)
            result = benchmark.run_benchmark(request, env)
            if any(trial["backend"] != record["backend"] for trial in result["trials"]):
                raise ValueError("product backend differs from requested matrix entry")
            record.update({"status": "qualified", "result": result})
        except Exception as error:
            record.update({"status": "failed", "error": str(error), "error_type": type(error).__name__})
            if (folder / "results.json").is_file():
                record["result"] = json.loads((folder / "results.json").read_text())
        suite["summary"] = summarize(suite["records"])
        suite["backend_proof_parity"] = qualify_parity(suite["records"])
        benchmark.write_result(args.out, suite)
    complete = all(record["status"] == "qualified" for record in suite["records"])
    parity = all(entry["status"] in {"identical", "single-backend"} for entry in suite["backend_proof_parity"])
    suite["status"] = "qualified" if complete and parity else "incomplete"
    benchmark.write_result(args.out, suite)
    print(json.dumps({"status": suite["status"], "summary": suite["summary"], "backend_proof_parity": suite["backend_proof_parity"]}, indent=2))
    return 0 if suite["status"] == "qualified" else 1


if __name__ == "__main__":
    sys.exit(main())
