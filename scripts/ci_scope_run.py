#!/usr/bin/env python3
"""Run one focused CI lane and publish a machine-readable timing receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.ci_scope_plan import POLICY, PlanError, strict_json, validate_policy, write_json


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def expand(command: list[str], output_dir: Path, commit: str) -> list[str]:
    replacements = {"{output_dir}": str(output_dir), "{commit}": commit}
    expanded: list[str] = []
    for argument in command:
        for token, replacement in replacements.items():
            argument = argument.replace(token, replacement)
        expanded.append(argument)
    return expanded


def run_lane(
    *, root: Path, policy: dict[str, Any], lane: str, output: Path,
    cache_mode: str, cache_root: Path | None, local_compatible: bool = False,
) -> dict[str, Any]:
    validate_policy(policy)
    spec = policy["lanes"].get(lane)
    if not isinstance(spec, dict):
        raise PlanError(f"unknown CI lane: {lane}")
    host = "macos" if sys.platform == "darwin" else "linux"
    required_host = spec["host"]
    compatible_host = host == required_host or (
        local_compatible and host == "macos" and required_host == "linux"
    )
    if not compatible_host:
        raise PlanError(f"CI lane {lane} requires {spec['host']}, current host is {host}")
    for command in spec["commands"]:
        targets = {argument for argument in command if not argument.startswith("-")}
        forbidden = sorted(
            target for target in targets
            if "benchmark" in target or ("profile" in target and not target.startswith("test-"))
        )
        if forbidden:
            raise PlanError(f"focused lane {lane} contains workload targets: {forbidden}")
    root = root.resolve(strict=True)
    output_dir = output.parent.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    environment = dict(os.environ)
    temporary_cache: tempfile.TemporaryDirectory[str] | None = None
    if cache_mode == "cold":
        temporary_cache = tempfile.TemporaryDirectory(prefix=f"stwo-ci-{lane}-")
        selected_cache = Path(temporary_cache.name)
    elif cache_mode == "warm":
        if cache_root is None:
            raise PlanError("warm cache mode requires --cache-root")
        selected_cache = cache_root.resolve()
        selected_cache.mkdir(parents=True, exist_ok=True)
    else:
        selected_cache = None
    if selected_cache is not None:
        environment.update({
            "STWO_CI_CACHE_DIR": str(selected_cache / "local"),
            "ZIG_LOCAL_CACHE_DIR": str(selected_cache / "zig-local"),
            "ZIG_GLOBAL_CACHE_DIR": str(selected_cache / "global"),
            "CARGO_TARGET_DIR": str(selected_cache / "cargo-target"),
        })
    records: list[dict[str, Any]] = []
    started_ns = time.monotonic_ns()
    status = "PASS"
    try:
        for ordinal, raw in enumerate(spec["commands"]):
            argv = expand(raw, output_dir, commit)
            command_started = time.monotonic_ns()
            result = subprocess.run(
                argv, cwd=root, env=environment, check=False, capture_output=True,
            )
            duration_ns = time.monotonic_ns() - command_started
            sys.stdout.buffer.write(result.stdout)
            sys.stderr.buffer.write(result.stderr)
            records.append({
                "ordinal": ordinal,
                "argv": argv,
                "duration_ns": duration_ns,
                "exit_code": result.returncode,
                "stdout_sha256": digest(result.stdout),
                "stderr_sha256": digest(result.stderr),
            })
            if result.returncode != 0:
                status = "FAIL"
                break
    finally:
        if temporary_cache is not None:
            temporary_cache.cleanup()
    clean = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=False,
    ).returncode == 0 and not subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"], cwd=root,
        check=True, capture_output=True,
    ).stdout.strip()
    receipt = {
        "schema": "stwo-focused-ci-timing-v1",
        "lane": lane,
        "host": host,
        "required_host": required_host,
        "host_machine": platform.machine(),
        "cache_mode": cache_mode,
        "commit": commit,
        "tree": tree,
        "clean": clean,
        "status": status,
        "duration_ns": time.monotonic_ns() - started_ns,
        "commands": records,
    }
    write_json(output, receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--lane", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-mode", choices=("inherit", "cold", "warm"), default="inherit")
    parser.add_argument("--cache-root", type=Path)
    parser.add_argument(
        "--local-compatible", action="store_true",
        help="permit Linux product lanes on a macOS development host",
    )
    args = parser.parse_args(argv)
    try:
        receipt = run_lane(
            root=args.root, policy=strict_json(args.policy), lane=args.lane,
            output=args.output, cache_mode=args.cache_mode, cache_root=args.cache_root,
            local_compatible=args.local_compatible,
        )
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError, PlanError) as error:
        print(f"CI scope run: FAIL: {error}", file=sys.stderr)
        return 2
    seconds = receipt["duration_ns"] / 1_000_000_000
    print(f"CI scope run: {receipt['status']} {receipt['lane']} {seconds:.3f}s")
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
