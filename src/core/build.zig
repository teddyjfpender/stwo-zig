const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const check_only = b.option(
        bool,
        "check-only",
        "Type-check focused roots without emitting or running test binaries",
    ) orelse false;

    const core = b.addModule("stwo_core", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = core });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Compile and test the stwo_core package");
    test_step.dependOn(&run_tests.step);

    const fields_step = addFocusedTests(b, target, optimize, check_only, .{
        .step = "test-fields",
        .description = "Run only core field arithmetic tests",
        .root = "fields_test_root.zig",
    });
    fields_step.dependOn(addNamedCoreTests(
        b,
        core,
        target,
        optimize,
        check_only,
        "fields/tests/m31.zig",
    ));

    const crypto_step = addFocusedTests(b, target, optimize, check_only, .{
        .step = "test-crypto",
        .description = "Run only core cryptographic primitive tests",
        .root = "crypto_test_root.zig",
    });
    const fri_step = addFocusedTests(b, target, optimize, check_only, .{
        .step = "test-fri",
        .description = "Run only core FRI tests",
        .root = "fri_test_root.zig",
    });
    fri_step.dependOn(addNamedCoreTests(
        b,
        core,
        target,
        optimize,
        check_only,
        "fri/tests.zig",
    ));
    const pcs_step = addFocusedTests(b, target, optimize, check_only, .{
        .step = "test-pcs",
        .description = "Run only core PCS tests",
        .root = "pcs_test_root.zig",
    });
    pcs_step.dependOn(addNamedCoreTests(
        b,
        core,
        target,
        optimize,
        check_only,
        "pcs/quotients/tests.zig",
    ));
    const geometry_root = b.createModule(.{
        .root_source_file = b.path("air_components_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const geometry_tests = b.addTest(.{
        .root_module = geometry_root,
        .filters = &GeometryTestGuard.expected_names,
    });
    const geometry_step = b.step("test-air-components", "Run component geometry and allocation rollback with exact test discovery");
    if (check_only) {
        geometry_step.dependOn(&geometry_tests.step);
    } else {
        const geometry_run = b.addRunArtifact(geometry_tests);
        geometry_run.has_side_effects = true;
        const guard = b.allocator.create(GeometryTestGuard) catch @panic("out of memory");
        guard.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "core component geometry test identity guard",
                .owner = b,
                .makeFn = GeometryTestGuard.make,
            }),
            .run = geometry_run,
        };
        guard.step.dependOn(&geometry_run.step);
        geometry_step.dependOn(&guard.step);
    }

    test_step.dependOn(fields_step);
    test_step.dependOn(crypto_step);
    test_step.dependOn(fri_step);
    test_step.dependOn(pcs_step);
    test_step.dependOn(geometry_step);
}

const GeometryTestGuard = struct {
    const expected_names = [_][]const u8{ "air components: orchestration", "pcs utils: concat cols" };
    step: std.Build.Step,
    run: *std.Build.Step.Run,

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const self: *GeometryTestGuard = @fieldParentPtr("step", step);
        const metadata = self.run.cached_test_metadata orelse
            return step.fail("component geometry run reported no test metadata", .{});
        if (metadata.names.len != expected_names.len)
            return step.fail("component geometry gate requires exactly {d} tests; found {d}", .{ expected_names.len, metadata.names.len });
        for (expected_names) |expected_name| {
            var found: usize = 0;
            for (0..metadata.names.len) |index| {
                if (std.mem.endsWith(u8, metadata.testName(@intCast(index)), expected_name)) found += 1;
            }
            if (found != 1) return step.fail("component geometry gate requires exactly one '{s}' test; found {d}", .{ expected_name, found });
        }
    }
};

const FocusedTest = struct {
    step: []const u8,
    description: []const u8,
    root: []const u8,
};

fn addFocusedTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_only: bool,
    spec: FocusedTest,
) *std.Build.Step {
    const root = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = root });
    const step = b.step(spec.step, spec.description);
    step.dependOn(if (check_only) &tests.step else &b.addRunArtifact(tests).step);
    return step;
}

fn addNamedCoreTests(
    b: *std.Build,
    core: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_only: bool,
    root_path: []const u8,
) *std.Build.Step {
    const root = b.createModule(.{
        .root_source_file = b.path(root_path),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("stwo_core", core);
    const tests = b.addTest(.{ .root_module = root });
    return if (check_only) &tests.step else &b.addRunArtifact(tests).step;
}
