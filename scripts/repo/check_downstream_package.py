#!/usr/bin/env python3
"""Compile and run a clean external package against public stwo-zig modules."""

from __future__ import annotations

import argparse
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
    const run = b.addRunArtifact(smoke);
    b.getInstallStep().dependOn(&run.step);
}
'''

MAIN_ZIG = r'''
const std = @import("std");
const core = @import("stwo_core");
const generic = @import("stwo_prover");
const compatibility = @import("stwo");

pub fn main() !void {
    const M31 = core.fields.m31.M31;
    const sum = M31.fromCanonical(13).add(M31.fromCanonical(29));
    if (!sum.eql(M31.fromCanonical(42))) return error.CoreSmokeFailed;
    if (!@hasDecl(generic, "prover") or !@hasDecl(generic, "backend"))
        return error.ProverSurfaceMissing;
    if (!@hasDecl(compatibility, "core") or !@hasDecl(compatibility, "prover"))
        return error.CompatibilitySurfaceMissing;
    try std.fs.File.stdout().writeAll("downstream package smoke: PASS\n");
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
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    repository = args.repo.resolve()
    with tempfile.TemporaryDirectory(
        prefix="stwo-zig-consumer-",
        dir=repository.parent,
    ) as directory:
        package = Path(directory).resolve()
        (package / "src").mkdir()
        (package / "build.zig").write_text(BUILD_ZIG, encoding="utf-8")
        (package / "src/main.zig").write_text(MAIN_ZIG, encoding="utf-8")
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
        run(["zig", "build", "-Doptimize=ReleaseFast"], package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
