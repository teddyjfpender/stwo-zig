#!/usr/bin/env python3
"""Compare focused Native CPU capabilities with the aggregate product."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def run(command: list[str], repository: Path) -> str:
    result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(
            f"registry parity command failed: {' '.join(command)}\n{result.stderr}"
        )
    return result.stdout


def native_applications(registry: dict[str, object]) -> list[dict[str, object]]:
    applications = registry.get("applications")
    if not isinstance(applications, list):
        raise SystemExit("registry applications must be an array")
    return sorted(
        (
            {
                "air": application["air"],
                "status": application["status"],
                "cpu": "cpu" in application["backends"],
            }
            for application in applications
            if (
                isinstance(application, dict)
                and "air" in application
                and "adapter" not in application
            )
        ),
        key=lambda application: str(application["air"]),
    )


def check(focused: Path, aggregate: Path, repository: Path) -> None:
    focused_registry = json.loads(run([str(focused), "applications"], repository))
    aggregate_registry = json.loads(run([str(aggregate), "applications"], repository))
    focused_apps = native_applications(focused_registry)
    aggregate_apps = native_applications(aggregate_registry)
    if focused_apps != aggregate_apps:
        raise SystemExit(
            "focused/aggregate Native registry mismatch:\n"
            f"focused={focused_apps!r}\naggregate={aggregate_apps!r}"
        )
    if not focused_apps:
        raise SystemExit("focused Native registry is empty")
    print(f"registry parity: PASS ({len(focused_apps)} Native AIRs)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--focused", type=Path)
    parser.add_argument("--aggregate", type=Path)
    args = parser.parse_args()
    repository = args.repo.resolve()
    if (args.focused is not None or args.aggregate is not None):
        if args.focused is None or args.aggregate is None:
            raise SystemExit("--focused and --aggregate must be supplied together")
        check(args.focused.resolve(), args.aggregate.resolve(), repository)
        return 0
    with tempfile.TemporaryDirectory(prefix="stwo-registry-parity-") as raw:
        prefix = Path(raw)
        run(
            [
                "zig",
                "build",
                "stwo-native-cpu",
                "stwo-zig",
                "-Doptimize=ReleaseFast",
                "-p",
                str(prefix),
            ],
            repository,
        )
        check(prefix / "bin/stwo-zig-native-cpu", prefix / "bin/stwo-zig", repository)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
