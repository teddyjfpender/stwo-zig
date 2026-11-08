#!/usr/bin/env python3
"""Run only the focused gates affected by the exact refs being pushed."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.ci_scope_plan import (
    CATALOG,
    POLICY,
    PlanError,
    git_changed_paths,
    select_lanes,
    strict_json,
    write_json,
)
from scripts.ci_scope_run import run_lane


OID = re.compile(r"^[0-9a-f]{40}$")
ZERO_OID = "0" * 40


def clear_git_local_environment(root: Path) -> None:
    """Prevent hook-local Git state from contaminating nested repositories."""
    result = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    for name in result.stdout.splitlines():
        os.environ.pop(name, None)


def parse_updates(lines: Iterable[str]) -> list[tuple[str, str]]:
    updates: list[tuple[str, str]] = []
    for ordinal, raw in enumerate(lines, 1):
        fields = raw.split()
        if len(fields) != 4:
            raise PlanError(f"pre-push update {ordinal} must contain four fields")
        _, local_oid, _, remote_oid = fields
        if not OID.fullmatch(local_oid) or not OID.fullmatch(remote_oid):
            raise PlanError(f"pre-push update {ordinal} has a malformed object ID")
        if local_oid != ZERO_OID:
            updates.append((remote_oid, local_oid))
    return updates


def git_output(root: Path, *argv: str) -> str | None:
    result = subprocess.run(
        ["git", *argv], cwd=root, check=False, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def new_ref_base(root: Path, head: str) -> str:
    for candidate in ("refs/remotes/origin/main", f"{head}^"):
        base = git_output(root, "merge-base", head, candidate)
        if base is not None and base != head:
            return base
    raise PlanError("cannot determine a comparison base for a new remote ref")


def changed_paths(root: Path, updates: list[tuple[str, str]]) -> tuple[str, list[str]]:
    if not updates:
        return "", []
    heads = {head for _, head in updates}
    current = git_output(root, "rev-parse", "HEAD")
    if len(heads) != 1 or current not in heads:
        raise PlanError("focused pre-push supports one update rooted at the checked-out HEAD")
    changed: set[str] = set()
    for remote, head in updates:
        base = new_ref_base(root, head) if remote == ZERO_OID else remote
        changed.update(git_changed_paths(root, base, head))
    return heads.pop(), sorted(changed)


def require_clean(root: Path) -> None:
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout
    if status:
        raise PlanError("focused pre-push requires a clean worktree")


def full_xcode_available() -> bool:
    selected = subprocess.run(
        ["xcode-select", "--print-path"], check=False, capture_output=True, text=True,
    )
    if selected.returncode != 0 or not selected.stdout.strip().startswith("/Applications/Xcode"):
        return False
    return all(
        subprocess.run(
            ["xcrun", "--sdk", "macosx", "--find", tool],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        for tool in ("metal", "metallib")
    )


def locally_runnable(
    lane: str, required_host: str, local_policy: str, host: str, has_full_xcode: bool,
) -> bool:
    if local_policy == "hosted":
        return False
    if required_host == "macos" and host != "macos":
        return False
    if lane == "metal_aot" and not has_full_xcode:
        return False
    return True


def run_focused_push(root: Path, head: str, paths: list[str], output_dir: Path) -> int:
    require_clean(root)
    catalog_started = time.monotonic_ns()
    catalog_result = subprocess.run(
        ["zig", "build", "product-matrix-identity", "-Doptimize=ReleaseFast"],
        cwd=root, check=False,
    )
    catalog_duration_ns = time.monotonic_ns() - catalog_started
    if catalog_result.returncode != 0:
        return catalog_result.returncode

    policy = strict_json(root / POLICY.relative_to(ROOT))
    catalog = strict_json(root / CATALOG.relative_to(ROOT))
    lanes, reasons = select_lanes(paths, catalog, policy)
    host = "macos" if sys.platform == "darwin" else "linux"
    has_full_xcode = host == "macos" and full_xcode_available()
    executed: list[str] = []
    deferred: list[str] = []
    started_ns = time.monotonic_ns()
    output_dir.mkdir(parents=True, exist_ok=True)
    status = "PASS"
    for lane in lanes:
        spec = policy["lanes"][lane]
        if not locally_runnable(
            lane, spec["host"], spec.get("local", "run"), host, has_full_xcode,
        ):
            deferred.append(lane)
            print(f"focused pre-push: DEFER {lane} to hosted {spec['host']} CI")
            continue
        print(f"focused pre-push: RUN {lane}", flush=True)
        receipt = run_lane(
            root=root,
            policy=policy,
            lane=lane,
            output=output_dir / f"{lane}.json",
            cache_mode="inherit",
            cache_root=None,
            local_compatible=True,
        )
        executed.append(lane)
        if receipt["status"] != "PASS":
            status = "FAIL"
            break

    summary = {
        "schema": "stwo-focused-pre-push-v1",
        "head": head,
        "host": host,
        "status": status,
        "changed_paths": paths,
        "selected_lanes": lanes,
        "executed_lanes": executed,
        "deferred_to_hosted_ci": deferred,
        "reasons": reasons,
        "catalog_duration_ns": catalog_duration_ns,
        "lane_duration_ns": time.monotonic_ns() - started_ns,
    }
    write_json(output_dir / "summary.json", summary)
    print(
        f"focused pre-push: {status}; {len(executed)} local, "
        f"{len(deferred)} hosted-only lanes"
    )
    return 0 if status == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        clear_git_local_environment(args.root)
        root = args.root.resolve(strict=True)
        if args.base is not None:
            resolved_head = git_output(root, "rev-parse", args.head)
            resolved_base = git_output(root, "rev-parse", args.base)
            if resolved_head is None or resolved_base is None:
                raise PlanError("manual focused pre-push revisions do not resolve")
            head, paths = resolved_head, git_changed_paths(root, resolved_base, resolved_head)
        else:
            head, paths = changed_paths(root, parse_updates(sys.stdin))
        if not paths:
            print("focused pre-push: no pushed changes")
            return 0
        output_dir = args.output_dir or root / "zig-out/ci/pre-push" / head
        return run_focused_push(root, head, paths, output_dir)
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError, PlanError) as error:
        print(f"focused pre-push: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
