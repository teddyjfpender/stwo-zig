const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.addModule("stwo_core", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = core });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Compile and test the stwo_core package");
    test_step.dependOn(&run_tests.step);

    const fields_step = addFocusedTests(b, target, optimize, .{
        .step = "test-fields",
        .description = "Run only core field arithmetic tests",
        .root = "fields_test_root.zig",
    });
    fields_step.dependOn(&addNamedCoreTests(
        b,
        core,
        target,
        optimize,
        "fields/tests/m31.zig",
    ).step);

    const crypto_step = addFocusedTests(b, target, optimize, .{
        .step = "test-crypto",
        .description = "Run only core cryptographic primitive tests",
        .root = "crypto_test_root.zig",
    });
    const fri_step = addFocusedTests(b, target, optimize, .{
        .step = "test-fri",
        .description = "Run only core FRI tests",
        .root = "fri_test_root.zig",
    });
    fri_step.dependOn(&addNamedCoreTests(
        b,
        core,
        target,
        optimize,
        "fri/tests.zig",
    ).step);
    const pcs_step = addFocusedTests(b, target, optimize, .{
        .step = "test-pcs",
        .description = "Run only core PCS tests",
        .root = "pcs_test_root.zig",
    });
    pcs_step.dependOn(&addNamedCoreTests(
        b,
        core,
        target,
        optimize,
        "pcs/quotients/tests.zig",
    ).step);

    test_step.dependOn(fields_step);
    test_step.dependOn(crypto_step);
    test_step.dependOn(fri_step);
    test_step.dependOn(pcs_step);
}

const FocusedTest = struct {
    step: []const u8,
    description: []const u8,
    root: []const u8,
};

fn addFocusedTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    spec: FocusedTest,
) *std.Build.Step {
    const root = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = root }));
    const step = b.step(spec.step, spec.description);
    step.dependOn(&tests.step);
    return step;
}

fn addNamedCoreTests(
    b: *std.Build,
    core: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    root_path: []const u8,
) *std.Build.Step.Run {
    const root = b.createModule(.{
        .root_source_file = b.path(root_path),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("stwo_core", core);
    return b.addRunArtifact(b.addTest(.{ .root_module = root }));
}
