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

/// BUILD-only retained test constructor. Private source layout stays with
/// this owner; consumers supply the already selected native module graph.
pub fn retainedTypedTestModule(b: *std.Build, native: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const source = native.root_source_file orelse @panic("selected frontend lacks source root");
    return createBoundRoot(b, native, source.dirname().path(b, "focused_test_retained_typed_components_upper.zig"), native, target, optimize);
}

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
    const postcard = rv32_package.module("stwo_riscv_rv32").import_table.get("interop_postcard") orelse
        @panic("canonical native codec injection missing");
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

    const owners = [_]OwnedModule{
        .{ .prefix = "isa/", .module = isa_package.module("stwo_riscv_isa") },
        .{ .prefix = "air_lang/", .module = air_lang_package.module("stwo_riscv_air_lang") },
        .{ .prefix = "memory/", .module = memory_package.module("stwo_riscv_memory") },
        .{ .prefix = "recursion_air/", .module = recursion_air_package.module("stwo_riscv_recursion_air") },
        .{ .prefix = "precompiles/", .module = precompiles_package.module("stwo_riscv_precompiles") },
        .{ .prefix = "rv32/", .module = rv32_package.module("stwo_riscv_rv32") },
        .{ .prefix = "rv64/", .module = rv64_package.module("stwo_riscv_rv64") },
        .{ .prefix = "recursion/", .module = recursion_package.module("stwo_riscv_recursion") },
        .{ .prefix = "testing/", .module = testing_package.module("stwo_riscv_testing") },
    };

    // Backend-generic proof harness exported as a separate test-only module.
    // Keeping it outside the frontend root avoids a dependency cycle while
    // CPU and Metal instantiate the exact same typed trace and transcript.
    const secp256k1_proof_harness = b.addModule("secp256k1_proof_harness", .{
        .root_source_file = b.path("compat/harnesses/secp256k1_proof_harness.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp256k1_proof_harness.addImport("stwo_core", core);
    secp256k1_proof_harness.addImport("stwo_prover_engine", prover);
    secp256k1_proof_harness.addImport("stwo_riscv_frontend", frontend);
    for (frontend.import_table.keys(), frontend.import_table.values()) |import_name, dependency|
        secp256k1_proof_harness.addImport(import_name, dependency);
    const keccakf_proof_harness = b.addModule("keccakf_proof_harness", .{
        .root_source_file = b.path("compat/harnesses/keccakf_proof_harness.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccakf_proof_harness.addImport("stwo_core", core);
    keccakf_proof_harness.addImport("stwo_prover_engine", prover);
    keccakf_proof_harness.addImport("stwo_riscv_frontend", frontend);
    for (frontend.import_table.keys(), frontend.import_table.values()) |import_name, dependency|
        keccakf_proof_harness.addImport(import_name, dependency);

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
    var complete_runs: [owners.len + 1]*std.Build.Step.Run = undefined;
    complete_runs[0] = run_tests;
    var previous_compile: *std.Build.Step = &tests.step;
    for (owners, 0..) |owner, index| {
        const owned_tests = b.addTest(.{ .root_module = owner.module });
        owned_tests.step.dependOn(previous_compile);
        previous_compile = &owned_tests.step;
        const run = b.addRunArtifact(owned_tests);
        run.has_side_effects = true;
        run.setEnvironmentVariable("STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS", "1");
        complete_runs[index + 1] = run;
        test_step.dependOn(TestCountFloor.requireName(b, run, signatureName(b, owner.module)));
    }
    test_step.dependOn(TestCountFloor.addMany(b, &complete_runs, test_floor));
    const build_run = b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("build.zig"), .target = b.graph.host, .optimize = optimize }) }));
    build_run.has_side_effects = true;
    const build_gate = TestCountFloor.addMany(b, &.{build_run}, 1);
    test_step.dependOn(build_gate);
    const build_step = b.step("test-build-components", "Check selected native modules and BUILD ownership");
    build_step.dependOn(build_gate);

    const manifest_mode = b.option(
        []const u8,
        "typed-air-manifest-mode",
        "Compatibility artifact mode: check (default) or update",
    ) orelse "check";
    const manifest_tool_root = createOwnedRoot(b, frontend, &owners, "compat_manifest_tool.zig", target, optimize);
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
        "src/frontends/riscv/air_lang/artifacts/m3-compat-v1",
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
    const frontier_tool_root = createOwnedRoot(b, frontend, &owners, "compat/assembly/rv32/materialization_frontier_tool.zig", target, optimize);
    frontier_tool_root.addImport("stwo_core", core);
    const frontier_tool = b.addExecutable(.{
        .name = "riscv-typed-air-frontier",
        .root_module = frontier_tool_root,
    });
    const run_frontier_tool = b.addRunArtifact(frontier_tool);
    run_frontier_tool.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    run_frontier_tool.addArgs(&.{
        frontier_mode,
        "src/frontends/riscv/air_lang/artifacts/h009-poseidon2-cost-v1",
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
    const static_profile_tool_root = createOwnedRoot(b, frontend, &owners, "compat/assembly/rv32/static_profile_registry_tool.zig", target, optimize);
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
        "src/frontends/riscv/air_lang/artifacts/p002-native-family-static-profile-v1",
    });
    b.step(
        "typed-air-static-profile",
        "Check or explicitly update the P-002 native-family profile artifacts",
    ).dependOn(&run_static_profile_tool.step);

    const layout_benchmark_root = createOwnedRoot(b, frontend, &owners, "compat/assembly/rv32/poseidon_layout_benchmark_tool.zig", target, optimize);
    layout_benchmark_root.addImport("stwo_core", core);
    layout_benchmark_root.addImport("stwo_prover_engine", prover);
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

    const keccak_projection_root = createOwnedRoot(b, frontend, &owners, "rv32/keccakf_adaptive_projection_tool.zig", target, optimize);
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
        addFocusedTests(b, frontend, &owners, target, optimize, check_only, spec);
}

const FocusedTest = @import("build_focused_tests.zig").Spec;

const OwnedModule = struct { prefix: []const u8, module: *std.Build.Module };

fn signatureName(b: *std.Build, module: *std.Build.Module) []const u8 {
    const root = module.root_source_file.?.getPath(b);
    const path = std.fs.path.join(b.allocator, &.{ std.fs.path.dirname(root).?, "package.contract.json" }) catch @panic("out of memory");
    const bytes = std.fs.cwd().readFileAlloc(b.allocator, path, 1 << 20) catch @panic("cannot read owned test contract");
    const value = std.json.parseFromSliceLeaky(std.json.Value, b.allocator, bytes, .{}) catch @panic("invalid owned test contract");
    const reference = value.object.get("api_contract").?.object.get("signature_tests").?.array.items[0].string;
    const separator = std.mem.indexOf(u8, reference, "::") orelse @panic("signature reference lacks test name");
    return reference[separator + 2 ..];
}

fn createOwnedRoot(b: *std.Build, frontend: *std.Build.Module, owners: []const OwnedModule, source: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    var provider = frontend;
    for (owners) |owner| if (std.mem.startsWith(u8, source, owner.prefix)) {
        provider = owner.module;
        break;
    };
    return createBoundRoot(b, provider, b.path(source), if (provider == frontend) frontend else null, target, optimize);
}

fn createBoundRoot(b: *std.Build, provider: *std.Build.Module, source: std.Build.LazyPath, frontend: ?*std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const root = b.createModule(.{ .root_source_file = source, .target = target, .optimize = optimize });
    for (provider.import_table.keys(), provider.import_table.values()) |name, dependency| root.addImport(name, dependency);
    if (frontend) |selected| root.addImport("stwo_riscv_frontend", selected);
    return root;
}

fn addFocusedTests(
    b: *std.Build,
    frontend: *std.Build.Module,
    owners: []const OwnedModule,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    check_only: bool,
    spec: FocusedTest,
) void {
    const roots = if (spec.partition_roots.len == 0) &.{spec.root} else spec.partition_roots;
    const runs = b.allocator.alloc(*std.Build.Step.Run, roots.len) catch @panic("out of memory");
    const owner = b.step(spec.step, spec.description);
    for (roots, 0..) |source, i| {
        const root = createOwnedRoot(b, frontend, owners, source, target, optimize);
        root.strip = spec.strip;
        root.error_tracing = spec.error_tracing;
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
pub const TestCountFloor = struct {
    step: std.Build.Step,
    runs: []const *std.Build.Step.Run,
    minimum: usize,
    required_name: ?[]const u8 = null,

    fn add(b: *std.Build, run: *std.Build.Step.Run, minimum: usize) *std.Build.Step {
        return addMany(b, &.{run}, minimum);
    }

    pub fn addMany(b: *std.Build, runs: []const *std.Build.Step.Run, minimum: usize) *std.Build.Step {
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

    fn requireName(b: *std.Build, run: *std.Build.Step.Run, name: []const u8) *std.Build.Step {
        const step = add(b, run, 1);
        const floor: *TestCountFloor = @fieldParentPtr("step", step);
        floor.required_name = name;
        return step;
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
        if (floor.required_name) |required| {
            var found = false;
            for (floor.runs) |run| {
                const metadata = run.cached_test_metadata.?;
                for (0..metadata.names.len) |i| found = found or std.mem.endsWith(u8, metadata.testName(@intCast(i)), required);
            }
            if (!found) return step.fail("owned contract signature was not executed: {s}", .{required});
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

test "retained BUILD constructor preserves selected modules and native ownership" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const directory = std.Build.Cache.Directory.cwd();
    const target = std.Build.ResolvedTarget{ .query = .{}, .result = @import("builtin").target };
    var graph = std.Build.Graph{
        .arena = a,
        .cache = .{ .gpa = a, .manifest_dir = std.fs.cwd() },
        .zig_exe = "zig",
        .env_map = std.process.EnvMap.init(a),
        .global_cache_root = directory,
        .zig_lib_directory = directory,
        .host = target,
        .time_report = false,
    };
    const b = try std.Build.create(&graph, directory, directory, &.{});
    const native = b.createModule(.{ .root_source_file = b.path("src/frontends/riscv/mod.zig") });
    const core = b.createModule(.{ .root_source_file = b.path("src/waist/core/mod.zig") });
    native.addImport("stwo_core", core);
    const module = retainedTypedTestModule(b, native, target, .Debug);
    try std.testing.expect(module != native);
    try std.testing.expect(module.import_table.get("stwo_core") == core);
    try std.testing.expectEqual(@as(usize, 1), native.import_table.count());
    try std.testing.expect(module.import_table.get("stwo_riscv_frontend") == native);
    try std.testing.expectEqual(@as(usize, 2), module.import_table.count());
    try std.testing.expectEqual(std.builtin.OptimizeMode.Debug, module.optimize.?);
    try std.testing.expect(std.mem.endsWith(u8, module.root_source_file.?.getPath(b), "focused_test_retained_typed_components_upper.zig"));
}
