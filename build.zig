const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module (importable by downstream packages).
    _ = b.addModule("stwo", .{ .root_source_file = b.path("src/stwo.zig") });

    // Unit tests.
    const tests = b.addTest(.{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Formatting gate.
    const fmt_cmd = b.addSystemCommand(&.{ "zig", "fmt", "--check", "build.zig", "src" });
    const fmt_step = b.step("fmt", "Check formatting (zig fmt --check)");
    fmt_step.dependOn(&fmt_cmd.step);
}
