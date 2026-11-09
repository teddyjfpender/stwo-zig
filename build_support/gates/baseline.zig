//! BG-00 immutable build-monorepo baseline gate.

const std = @import("std");

pub fn addGate(b: *std.Build) void {
    const check = b.addSystemCommand(&.{
        "python3",
        "scripts/repo/check_build_monorepo_baseline.py",
    });
    const step = b.step(
        "build-monorepo-baseline",
        "Validate the immutable pre-migration build and performance baseline",
    );
    step.dependOn(&check.step);
}
