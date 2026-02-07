const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module (importable by downstream packages).
    _ = b.addModule("stwo", .{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests.
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Deterministic parity vectors gate (Rust upstream -> JSON fixtures).
    const vectors_cmd = b.addSystemCommand(&.{ "python3", "scripts/parity_fields.py", "--skip-zig" });
    const vectors_step = b.step("vectors", "Validate committed parity vectors");
    vectors_step.dependOn(&vectors_cmd.step);

    // Formatting gate.
    const fmt_cmd = b.addSystemCommand(&.{ "zig", "fmt", "--check", "build.zig", "src", "tools" });
    const fmt_step = b.step("fmt", "Check formatting (zig fmt --check)");
    fmt_step.dependOn(&fmt_cmd.step);
}
