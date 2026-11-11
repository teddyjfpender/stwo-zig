#!/usr/bin/env python3
"""Compile and run a clean external package against public stwo-zig modules."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


BUILD_ZIG = r'''
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const stwo_zig = b.dependency("stwo_zig", .{ .target = target, .optimize = optimize });
    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("stwo_core", stwo_zig.module("stwo_core"));
    root.addImport("stwo_prover", stwo_zig.module("stwo_prover"));
    root.addImport("stwo", stwo_zig.module("stwo"));
    const smoke = b.addExecutable(.{ .name = "consumer-smoke", .root_module = root });
    b.installArtifact(smoke);
    const run = b.addRunArtifact(smoke);
    run.has_side_effects = true;
    b.getInstallStep().dependOn(&run.step);
}
'''



def run(command: list[str], cwd: Path) -> None:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    print(result.stdout, end="")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    repository = args.repo.resolve()
    with tempfile.TemporaryDirectory(
        prefix="stwo-zig-consumer-",
        dir=repository.parent,
    ) as directory:
        package = Path(directory).resolve()
        (package / "src").mkdir()
        (package / "build.zig").write_text(BUILD_ZIG, encoding="utf-8")
        (package / "src/main.zig").write_bytes(
            (repository / "src/products/stwo/tests/public_modules.zig").read_bytes()
        )
        package_path = json.dumps(os.path.relpath(repository, package))
        (package / "build.zig.zon").write_text(
            ".{\n"
            "    .name = .stwo_zig_consumer_smoke,\n"
            "    .version = \"0.0.0\",\n"
            "    .fingerprint = 0x3e7cc616da25865a,\n"
            "    .dependencies = .{ .stwo_zig = .{ .path = " + package_path + " } },\n"
            "    .paths = .{ \"build.zig\", \"build.zig.zon\", \"src\" },\n"
            "}\n",
            encoding="utf-8",
        )
        run(["zig", "build", "--prefix", str(package / "zig-out"), "-Doptimize=ReleaseFast", "-j1"], package)
        image = package / "zig-out/bin/consumer-smoke"
        if not image.is_file():
            raise RuntimeError("external consumer did not install its binary")
        print(json.dumps({
            "external_consumer_binary_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "binary_bytes": image.stat().st_size,
            "fixture_sha256": hashlib.sha256((package / "src/main.zig").read_bytes()).hexdigest(),
            "optimize": "ReleaseFast",
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
