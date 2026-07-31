const std = @import("std");

/// Fewest tests this package's test binary must contain.
///
/// Measured on this tree: 473. Zig collects a `test` only from a file it was
/// made to analyse, so for as long as this step existed it silently compiled 319
/// of the 461 named tests in the package -- `refAllDecls` in a `mod.zig` does not
/// pull a file's tests in, and nothing said so. A binary that compiled almost
/// nothing still exits 0 in milliseconds, so the count is the only thing that
/// distinguishes this step from an empty shell.
///
/// `mod.zig` reaches every test-bearing file through `test_inventory.zig`, and
/// `test_inventory_test.zig` fails when a file is missing from that list. This
/// floor is the backstop for the wiring itself. Raise it deliberately as the
/// suite grows; never lower it to make a build pass.
const test_floor = 440;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const frontend = b.addModule("stwo_riscv_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_prover_api", prover_api);
    frontend.addImport("stwo_prover_engine", prover);

    const tests = b.addTest(.{ .root_module = frontend });
    const run_tests = b.addRunArtifact(tests);
    // ReleaseFast production skips the duplicate pre-commit semantic pass.
    // The package CI lane opts back in so the validator and its exact
    // InvalidSemanticWitness verdict remain exercised in the shipping mode.
    run_tests.setEnvironmentVariable(
        "STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS",
        "1",
    );
    // The floor reads the run's test-name table, which only the invocation that
    // actually executed the binary populates: a cache hit leaves it null and the
    // floor would then have to fail closed on every repeat of a correct run.
    // Re-running an already compiled suite costs its runtime, under a second.
    run_tests.has_side_effects = true;
    const test_step = b.step(
        "test",
        "Compile and test the stwo_riscv_frontend package",
    );
    test_step.dependOn(TestCountFloor.add(b, run_tests, test_floor));

    addFocusedTests(b, core, target, optimize, .{
        .step = "test-isa",
        .description = "Run only RISC-V ISA authority and decoder tests",
        .root = "isa_test_root.zig",
    });
    addFocusedTests(b, core, target, optimize, .{
        .step = "test-runner",
        .description = "Run only RISC-V execution-runner tests",
        .root = "runner_test_root.zig",
    });
    addFocusedTests(b, core, target, optimize, .{
        .step = "test-air-semantics",
        .description = "Run only RISC-V instruction-family AIR tests",
        .root = "air_semantics_test_root.zig",
    });
}

const FocusedTest = struct {
    step: []const u8,
    description: []const u8,
    root: []const u8,
};

fn addFocusedTests(
    b: *std.Build,
    core: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    spec: FocusedTest,
) void {
    const root = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = target,
        .optimize = optimize,
    });
    root.addImport("stwo_core", core);
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = root }));
    b.step(spec.step, spec.description).dependOn(&tests.step);
}

/// Turns "the binary lost its tests" from a zero exit into a named failure.
///
/// Deliberately duplicated rather than shared with
/// `build_support/products/riscv_test_filter.zig`: this package builds
/// standalone, so it cannot import the repository's build support, and the
/// product gate's floor cannot cover a lane this build file owns.
const TestCountFloor = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    minimum: usize,

    fn add(b: *std.Build, run: *std.Build.Step.Run, minimum: usize) *std.Build.Step {
        const floor = b.allocator.create(TestCountFloor) catch @panic("out of memory");
        floor.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "stwo_riscv_frontend test count floor",
                .owner = b,
                .makeFn = make,
            }),
            .run = run,
            .minimum = minimum,
        };
        floor.step.dependOn(&run.step);
        return &floor.step;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const floor: *TestCountFloor = @fieldParentPtr("step", step);
        const metadata = floor.run.cached_test_metadata orelse return step.fail(
            "the run reported no test names, so the package's test count could not be verified",
            .{},
        );
        if (metadata.names.len >= floor.minimum) return;
        return step.fail(
            \\this package compiled {d} tests; its own step requires at least {d}.
            \\  Zig collects a test only from a file it analysed, so a file that fell out of
            \\  test_inventory.zig is compiled by nothing and still reports green. Restore the
            \\  import, or move `test_floor` in this build file deliberately.
        , .{ metadata.names.len, floor.minimum });
    }
};
