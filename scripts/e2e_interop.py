#!/usr/bin/env python3
"""Cross-language interoperability gate for example proof paths.

This harness currently enforces a fixture-bridge interoperability mode:
1. Rust deterministic fixture generation/check (`tools/stwo-vector-gen`).
2. Zig wrapper proof-path roundtrip and rejection tests.
3. Optional upstream Rust examples crate build smoke.

The report is written as JSON for CI/handoff consumption.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "e2e_interop_report.json"
EXAMPLES_REPORT = ROOT / "vectors" / "reports" / "e2e_examples_fixture_report.json"
GEN_MANIFEST = ROOT / "tools" / "stwo-vector-gen" / "Cargo.toml"


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=cwd or ROOT, env=env, check=True)


def timed_step(
    name: str,
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> dict:
    start = time.perf_counter()
    run(cmd, cwd=cwd, env=env)
    elapsed = time.perf_counter() - start
    return {
        "name": name,
        "command": cmd,
        "cwd": str((cwd or ROOT).relative_to(ROOT)) if (cwd or ROOT).is_relative_to(ROOT) else str(cwd or ROOT),
        "seconds": round(elapsed, 6),
        "status": "ok",
    }


def maybe_find_upstream_examples_manifest() -> Path | None:
    candidates = sorted(
        Path.home().glob(".cargo/git/checkouts/stwo-*/*/crates/examples/Cargo.toml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-language interoperability gate")
    parser.add_argument("--count", type=int, default=256)
    parser.add_argument(
        "--skip-upstream-examples-check",
        action="store_true",
        help="Skip optional upstream examples cargo check",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    args = parser.parse_args()

    steps: list[dict] = []

    # 1) Rust fixture generation/check + schema parity (without rerunning full zig test gate).
    steps.append(
        timed_step(
            "examples_fixture_bridge",
            [
                "python3",
                "scripts/e2e_examples.py",
                "--count",
                str(args.count),
                "--skip-zig",
                "--report-out",
                str(EXAMPLES_REPORT),
            ],
        )
    )

    # 2) Rust-side toolchain gate for parity fixture producer.
    steps.append(
        timed_step(
            "rust_vector_gen_check",
            ["cargo", "check", "--manifest-path", str(GEN_MANIFEST)],
        )
    )

    # 3) Zig wrapper proof-path gates.
    wrapper_filters = [
        "examples state_machine: prove/verify wrapper roundtrip",
        "examples state_machine: verify wrapper rejects tampered statement",
        "examples xor: prove/verify wrapper roundtrip",
        "examples xor: verify wrapper rejects statement mismatch",
    ]
    for test_filter in wrapper_filters:
        steps.append(
            timed_step(
                f"zig_{test_filter}",
                [
                    "zig",
                    "test",
                    "src/stwo.zig",
                    "--test-filter",
                    test_filter,
                ],
            )
        )

    # 4) Optional upstream examples build smoke (requires nightly feature gate env).
    upstream_status: dict
    if args.skip_upstream_examples_check:
        upstream_status = {
            "status": "skipped",
            "reason": "--skip-upstream-examples-check",
        }
    else:
        manifest = maybe_find_upstream_examples_manifest()
        if manifest is None:
            upstream_status = {
                "status": "skipped",
                "reason": "upstream checkout not present under ~/.cargo/git/checkouts",
            }
        else:
            env = dict(os.environ)
            env["RUSTC_BOOTSTRAP"] = "1"
            step = timed_step(
                "upstream_examples_cargo_check",
                ["cargo", "check", "-q"],
                cwd=manifest.parent,
                env=env,
            )
            step["manifest"] = str(manifest)
            steps.append(step)
            upstream_status = {
                "status": "ok",
                "manifest": str(manifest),
            }

    report = {
        "status": "ok",
        "exchange_mode": "fixture_bridge",
        "summary": {
            "mandatory_steps": len([s for s in steps if s["status"] == "ok"]),
            "optional_upstream_examples": upstream_status,
        },
        "steps": steps,
        "artifacts": {
            "examples_parity_report": str(EXAMPLES_REPORT.relative_to(ROOT)),
        },
    }

    out = args.report_out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    latest = out.parent / "latest_e2e_interop_report.json"
    if latest != out:
        shutil.copyfile(out, latest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
