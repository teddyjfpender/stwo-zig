const std = @import("std");

/// Fewest tests this package's test binary must contain.
///
/// Measured floor on this tree: 1061. Zig collects a `test` only from a file it was
/// made to analyse, so before the explicit inventory this step silently compiled
/// only 319 of the then-461 named tests -- `refAllDecls` in a `mod.zig` does not
/// pull a file's tests in, and nothing said so. A binary that compiled almost
/// nothing still exits 0 in milliseconds, so the count is the only thing that
/// distinguishes this step from an empty shell.
///
/// `mod.zig` reaches every test-bearing file through `test_inventory.zig`, and
/// `test_inventory_test.zig` fails when a file is missing from that list. This
/// floor is the backstop for the wiring itself. Raise it deliberately as the
/// suite grows; never lower it to make a build pass.
const test_floor = 1103;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const check_only = b.option(
        bool,
        "check-only",
        "Type-check focused roots without emitting or running test binaries",
    ) orelse false;
    const dependency_options = .{ .target = target, .optimize = optimize };
    const isa_package = b.dependency("stwo_riscv_isa", dependency_options);
    const air_lang_package = b.dependency("stwo_riscv_air_lang", dependency_options);
    const memory_package = b.dependency("stwo_riscv_memory", dependency_options);
    const recursion_air_package = b.dependency("stwo_riscv_recursion_air", dependency_options);
    const precompiles_package = b.dependency("stwo_riscv_precompiles", dependency_options);
    const rv32_package = b.dependency("stwo_riscv_rv32", dependency_options);
    const rv64_package = b.dependency("stwo_riscv_rv64", dependency_options);
    const recursion_package = b.dependency("stwo_riscv_recursion", dependency_options);
    const testing_package = b.dependency("stwo_riscv_testing", dependency_options);

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const proof_wire = b.createModule(.{
        .root_source_file = b.path("../../waist/proof_wire/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    proof_wire.addImport("stwo_core", core);
    const postcard = b.createModule(.{
        .root_source_file = b.path("../../waist/recursion_wire/postcard/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    postcard.addImport("stwo_core", core);
    postcard.addImport("stwo_proof_wire", proof_wire);
    const typed_air_artifacts = b.createModule(.{
        .root_source_file = b.path(
            "air/lang/artifacts/embedded.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    const typed_air_h009_artifacts = b.createModule(.{
        .root_source_file = b.path(
            "air/lang/artifacts/h009_embedded.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    const typed_air_h010_artifacts = b.createModule(.{
        .root_source_file = b.path(
            "air/lang/artifacts/h010_embedded.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    const frontend = b.addModule("stwo_riscv_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_riscv_isa", isa_package.module("stwo_riscv_isa"));
    frontend.addImport("stwo_riscv_air_lang", air_lang_package.module("stwo_riscv_air_lang"));
    frontend.addImport("stwo_riscv_memory", memory_package.module("stwo_riscv_memory"));
    frontend.addImport("stwo_riscv_recursion_air", recursion_air_package.module("stwo_riscv_recursion_air"));
    frontend.addImport("stwo_riscv_precompiles", precompiles_package.module("stwo_riscv_precompiles"));
    frontend.addImport("stwo_riscv_rv32", rv32_package.module("stwo_riscv_rv32"));
    frontend.addImport("stwo_riscv_rv64", rv64_package.module("stwo_riscv_rv64"));
    frontend.addImport("stwo_riscv_recursion", recursion_package.module("stwo_riscv_recursion"));
    frontend.addImport("stwo_riscv_testing", testing_package.module("stwo_riscv_testing"));
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_prover_api", prover_api);
    frontend.addImport("stwo_prover_engine", prover);
    frontend.addImport("interop_postcard", postcard);
    // Test-only consumers import this name explicitly. Production frontend
    // modules never reference the design artifact package.
    frontend.addImport("typed_air_artifacts", typed_air_artifacts);
    frontend.addImport("typed_air_h009_artifacts", typed_air_h009_artifacts);
    frontend.addImport("typed_air_h010_artifacts", typed_air_h010_artifacts);

    // Backend-generic proof harness exported as a separate test-only module.
    // Keeping it outside the frontend root avoids a dependency cycle while
    // CPU and Metal instantiate the exact same typed trace and transcript.
    const secp256k1_proof_harness = b.addModule("secp256k1_proof_harness", .{
        .root_source_file = b.path("testing/secp256k1_proof_harness.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp256k1_proof_harness.addImport("stwo_core", core);
    secp256k1_proof_harness.addImport("stwo_prover_engine", prover);
    secp256k1_proof_harness.addImport("stwo_riscv_frontend", frontend);
    const keccakf_proof_harness = b.addModule("keccakf_proof_harness", .{
        .root_source_file = b.path("testing/keccakf_proof_harness.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccakf_proof_harness.addImport("stwo_core", core);
    keccakf_proof_harness.addImport("stwo_prover_engine", prover);
    keccakf_proof_harness.addImport("stwo_riscv_frontend", frontend);

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

    addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, .{
        .step = "test-vm-leaf-context-v2",
        .description = "Test SegmentV2 verifier-instance and capture authority",
        .root = "vm_leaf_context_test_root.zig",
        .imports_prover_engine = true,
        .filters = &.{ "SegmentV2 VM leaf ContextV2", "Ethereum selected base claim admission" },
        .minimum = 4,
    });

    const poseidon_frontier_test_root = b.createModule(.{
        .root_source_file = b.path(
            "poseidon_materialization_frontier_test_root.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    poseidon_frontier_test_root.addImport("stwo_core", core);
    poseidon_frontier_test_root.addImport("stwo_prover_engine", prover);
    const poseidon_frontier_tests = b.addTest(.{
        .root_module = poseidon_frontier_test_root,
    });
    const run_poseidon_frontier_tests = b.addRunArtifact(
        poseidon_frontier_tests,
    );
    b.step(
        "test-poseidon-materialization-frontier",
        "Run focused typed-Poseidon layout and quotient-frontier tests",
    ).dependOn(&run_poseidon_frontier_tests.step);

    const manifest_mode = b.option(
        []const u8,
        "typed-air-manifest-mode",
        "Compatibility artifact mode: check (default) or update",
    ) orelse "check";
    const manifest_tool_root = b.createModule(.{
        .root_source_file = b.path("compat_manifest_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    manifest_tool_root.addImport("stwo_core", core);
    manifest_tool_root.addImport("stwo_prover_engine", prover);
    const manifest_tool = b.addExecutable(.{
        .name = "riscv-typed-air-manifest",
        .root_module = manifest_tool_root,
    });
    const run_manifest_tool = b.addRunArtifact(manifest_tool);
    run_manifest_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_manifest_tool.addArgs(&.{
        manifest_mode,
        "src/frontends/riscv/air/lang/artifacts/m3-compat-v1",
    });
    b.step(
        "typed-air-manifest",
        "Check or explicitly update typed-AIR compatibility artifacts",
    ).dependOn(&run_manifest_tool.step);

    const frontier_mode = b.option(
        []const u8,
        "typed-air-frontier-mode",
        "H-009 Poseidon cost-frontier artifact mode: check (default) or update",
    ) orelse "check";
    const frontier_tool_root = b.createModule(.{
        .root_source_file = b.path("materialization_frontier_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontier_tool_root.addImport("stwo_core", core);
    const frontier_tool = b.addExecutable(.{
        .name = "riscv-typed-air-frontier",
        .root_module = frontier_tool_root,
    });
    const run_frontier_tool = b.addRunArtifact(frontier_tool);
    run_frontier_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_frontier_tool.addArgs(&.{
        frontier_mode,
        "src/frontends/riscv/air/lang/artifacts/h009-poseidon2-cost-v1",
    });
    b.step(
        "typed-air-frontier",
        "Check or explicitly update the H-009 Poseidon cost-frontier artifacts",
    ).dependOn(&run_frontier_tool.step);

    const static_profile_mode = b.option(
        []const u8,
        "typed-air-static-profile-mode",
        "P-002 native-family profile artifact mode: check (default) or update",
    ) orelse "check";
    const static_profile_tool_root = b.createModule(.{
        .root_source_file = b.path("static_profile_registry_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    static_profile_tool_root.addImport("stwo_core", core);
    static_profile_tool_root.addImport("stwo_prover_api", prover_api);
    static_profile_tool_root.addImport("interop_postcard", postcard);
    const static_profile_tool = b.addExecutable(.{
        .name = "riscv-typed-air-static-profile",
        .root_module = static_profile_tool_root,
    });
    const run_static_profile_tool = b.addRunArtifact(static_profile_tool);
    run_static_profile_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_static_profile_tool.addArgs(&.{
        static_profile_mode,
        "src/frontends/riscv/air/lang/artifacts/p002-native-family-static-profile-v1",
    });
    b.step(
        "typed-air-static-profile",
        "Check or explicitly update the P-002 native-family profile artifacts",
    ).dependOn(&run_static_profile_tool.step);

    const layout_benchmark_root = b.createModule(.{
        .root_source_file = b.path("poseidon_layout_benchmark_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    layout_benchmark_root.addImport("stwo_core", core);
    layout_benchmark_root.addImport("stwo_prover_engine", prover);
    layout_benchmark_root.addImport(
        "typed_air_h009_artifacts",
        typed_air_h009_artifacts,
    );
    layout_benchmark_root.addImport(
        "typed_air_h010_artifacts",
        typed_air_h010_artifacts,
    );
    const layout_benchmark = b.addExecutable(.{
        .name = "riscv-poseidon-layout-benchmark",
        .root_module = layout_benchmark_root,
    });
    // The process-resource adapter uses Darwin/Linux libc rusage surfaces.
    layout_benchmark.linkLibC();
    const run_layout_benchmark = b.addRunArtifact(layout_benchmark);
    run_layout_benchmark.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    if (b.args) |args|
        run_layout_benchmark.addArgs(args)
    else
        run_layout_benchmark.addArg("check");
    b.step(
        "typed-air-layout-benchmark",
        "Check H-010 correctness or run one isolated experimental sample",
    ).dependOn(&run_layout_benchmark.step);
    b.step(
        "typed-air-layout-benchmark-install",
        "Install the isolated H-010 runner for fresh-process host sampling",
    ).dependOn(&b.addInstallArtifact(layout_benchmark, .{}).step);

    const keccak_projection_root = b.createModule(.{
        .root_source_file = b.path("keccakf_adaptive_projection_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccak_projection_root.addImport("stwo_core", core);
    keccak_projection_root.addImport("stwo_prover_engine", prover);
    const keccak_projection = b.addExecutable(.{
        .name = "riscv-keccak-adaptive-projection",
        .root_module = keccak_projection_root,
    });
    keccak_projection.linkLibC();
    const run_keccak_projection = b.addRunArtifact(keccak_projection);
    if (b.args) |args| run_keccak_projection.addArgs(args);
    b.step(
        "keccakf-adaptive-corpus-projection",
        "Create an exact adaptive-Keccak committed-cell projection receipt",
    ).dependOn(&run_keccak_projection.step);
    b.step(
        "keccakf-adaptive-corpus-projection-install",
        "Install the retained-corpus adaptive-Keccak projection tool",
    ).dependOn(&b.addInstallArtifact(keccak_projection, .{}).step);

    for (@import("build_focused_tests.zig").specs) |spec|
        addFocusedTests(b, core, prover, prover_api, postcard, typed_air_artifacts, target, optimize, check_only, spec);
}

const FocusedTest = @import("build_focused_tests.zig").Spec;

fn addFocusedTests(
    b: *std.Build,
    core: *std.Build.Module,
    prover: *std.Build.Module,
    prover_api: *std.Build.Module,
    postcard: *std.Build.Module,
    typed_air_artifacts: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_only: bool,
    spec: FocusedTest,
) void {
    const roots = if (spec.partition_roots.len == 0) &.{spec.root} else spec.partition_roots;
    const runs = b.allocator.alloc(*std.Build.Step.Run, roots.len) catch @panic("out of memory");
    const owner = b.step(spec.step, spec.description);
    for (roots, 0..) |source, i| {
        const root = b.createModule(.{
            .root_source_file = b.path(source),
            .target = target,
            .optimize = optimize,
            .strip = spec.strip,
            .error_tracing = spec.error_tracing,
        });
        root.addImport("stwo_core", core);
        root.addImport("stwo_prover_api", prover_api);
        root.addImport("interop_postcard", postcard);
        if (spec.imports_prover_engine)
            root.addImport("stwo_prover_engine", prover);
        if (spec.imports_typed_air_artifacts)
            root.addImport("typed_air_artifacts", typed_air_artifacts);
        const tests = b.addTest(.{ .root_module = root, .filters = spec.filters });
        if (check_only) {
            owner.dependOn(&tests.step);
        } else {
            const run = b.addRunArtifact(tests);
            run.has_side_effects = true;
            runs[i] = run;
            owner.dependOn(&run.step);
        }
    }
    if (!check_only and spec.minimum != 0)
        owner.dependOn(TestCountFloor.addMany(b, runs, spec.minimum));
}

/// Turns "the binary lost its tests" from a zero exit into a named failure.
///
/// Deliberately duplicated rather than shared with
/// `build_support/products/riscv_test_filter.zig`: this package builds
/// standalone, so it cannot import the repository's build support, and the
/// product gate's floor cannot cover a lane this build file owns.
const TestCountFloor = struct {
    step: std.Build.Step,
    runs: []const *std.Build.Step.Run,
    minimum: usize,

    fn add(b: *std.Build, run: *std.Build.Step.Run, minimum: usize) *std.Build.Step {
        return addMany(b, &.{run}, minimum);
    }

    fn addMany(b: *std.Build, runs: []const *std.Build.Step.Run, minimum: usize) *std.Build.Step {
        const floor = b.allocator.create(TestCountFloor) catch @panic("out of memory");
        floor.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "stwo_riscv_frontend test count floor",
                .owner = b,
                .makeFn = make,
            }),
            .runs = b.allocator.dupe(*std.Build.Step.Run, runs) catch @panic("out of memory"),
            .minimum = minimum,
        };
        for (runs) |run| floor.step.dependOn(&run.step);
        return &floor.step;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const floor: *TestCountFloor = @fieldParentPtr("step", step);
        var names = std.StringHashMap(void).init(step.owner.allocator);
        defer names.deinit();
        var count: usize = 0;
        for (floor.runs) |run| {
            const metadata = run.cached_test_metadata orelse return step.fail(
                "the run reported no test names, so the package's test count could not be verified",
                .{},
            );
            if (floor.runs.len == 1) {
                count = metadata.names.len;
            } else {
                // Shared dependencies run in each image, but cannot compensate
                // for a missing partition in the complete target's floor.
                for (0..metadata.names.len) |i|
                    try names.put(metadata.testName(@intCast(i)), {});
                count = names.count();
            }
        }
        if (count >= floor.minimum) return;
        return step.fail(
            \\this package compiled {d} tests; its own step requires at least {d}.
            \\  Zig collects a test only from a file it analysed, so a file that fell out of
            \\  test_inventory.zig is compiled by nothing and still reports green. Restore the
            \\  import, or move `test_floor` in this build file deliberately.
        , .{ count, floor.minimum });
    }
};
