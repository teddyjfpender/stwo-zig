//! Test-only build that joins `stwo_circuit_frontend` and `stwo_cairo_frontend`
//! to assert their shared Cairo slot order. Neither package depends on the
//! other; only this conformance root sees both.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const root = b.createModule(.{
        .root_source_file = b.path("circuit_cairo_slot_order_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    root.addImport(
        "stwo_circuit_frontend",
        b.dependency("stwo_circuit_frontend", dependency_options).module("stwo_circuit_frontend"),
    );
    root.addImport(
        "stwo_cairo_frontend",
        b.dependency("stwo_cairo_frontend", dependency_options).module("stwo_cairo_frontend"),
    );
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = root }));
    tests.setCwd(.{ .cwd_relative = b.pathFromRoot("../..") });
    b.step("test", "Assert the circuit projection's Cairo slot order equals the Cairo claim registry").dependOn(&tests.step);
}
