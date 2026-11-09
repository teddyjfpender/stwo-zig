const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };
    const check_only = b.option(bool, "check-only", "Type-check focused tests and the fixture receiver without code generation or execution") orelse false;

    const publication_root = b.createModule(.{ .root_source_file = b.path("rv64_recursion/om31_native/publication.zig"), .target = target, .optimize = optimize });
    const publication_tests = b.addTest(.{ .root_module = publication_root });
    b.step("test-recursion-publication", "Test bounded root/tree binding and durable publication without prover imports").dependOn(testDependency(b, publication_tests, check_only, 0));
    const dag_root = b.createModule(.{ .root_source_file = b.path("rv64_recursion/om31_native/ready_dag.zig"), .target = target, .optimize = optimize });
    const dag_tests = b.addTest(.{ .root_module = dag_root });
    b.step("test-recursion-dag", "Test recursion device ownership, worker budgets and ready dispatch without prover imports").dependOn(testDependency(b, dag_tests, check_only, 0));

    const artifact_store = b.dependency(
        "stwo_artifact_store",
        dependency_options,
    ).module("stwo_artifact_store");
    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const cpu_backend = b.dependency(
        "stwo_cpu_backend",
        dependency_options,
    ).module("stwo_cpu_backend");
    const circuit_frontend = b.dependency("stwo_circuit_frontend", dependency_options).module("stwo_circuit_frontend");
    const frontend_dependency = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    );
    const frontend = frontend_dependency.module("stwo_riscv_frontend");
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");
    const integration = b.addModule("stwo_riscv_cpu_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_artifact_store", artifact_store);
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_proof_wire", postcard.import_table.get("stwo_proof_wire") orelse @panic("canonical postcard module is missing proof wire"));
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    integration.addImport("stwo_circuit_frontend", circuit_frontend);
    integration.addImport("interop_postcard", postcard);

    for ([_]struct { step: []const u8, root: []const u8, minimum: usize }{
        .{ .step = "test-blake3-proof-contracts", .root = "blake3_proof_contract_test_root.zig", .minimum = 22 },
        .{ .step = "test-word16-image-program-contracts", .root = "word16_image_program_contract_test_root.zig", .minimum = 23 },
        .{ .step = "test-distributed-binary-contracts", .root = "distributed_binary_contract_test_root.zig", .minimum = 13 },
        .{ .step = "test-division-contracts", .root = "division_contract_test_root.zig", .minimum = 7 },
        .{ .step = "test-services-truth-contracts", .root = "services_truth_contract_test_root.zig", .minimum = 22 },
    }) |spec| {
        const root = b.createModule(.{ .root_source_file = b.path(spec.root), .target = target, .optimize = optimize, .strip = false, .error_tracing = true });
        var imports = integration.import_table.iterator();
        while (imports.next()) |entry| root.addImport(entry.key_ptr.*, entry.value_ptr.*);
        const tests = b.addTest(.{ .root_module = root });
        b.step(spec.step, "Check retained live regression contracts").dependOn(testDependency(b, tests, check_only, spec.minimum));
    }

    const device_projection_root = b.createModule(.{ .root_source_file = b.path("device_cpu_projection_test_root.zig"), .target = target, .optimize = optimize });
    device_projection_root.addImport("stwo_core", core);
    device_projection_root.addImport("stwo_prover_api", prover_api);
    device_projection_root.addImport("stwo_prover_engine", prover);
    device_projection_root.addImport("stwo_cpu_backend", cpu_backend);
    device_projection_root.addImport("stwo_riscv_frontend", frontend);
    device_projection_root.addImport("interop_postcard", postcard);
    const projection_tests = b.addTest(.{ .root_module = device_projection_root, .filters = &.{"device CPU projection"} });
    b.step("test-device-cpu-projection", "Verify narrow CPU capture/device geometry ownership without materializing MAIN").dependOn(testDependency(b, projection_tests, check_only, 0));

    const native_gkr_root = b.createModule(.{ .root_source_file = b.path("rv64_native_gkr_test_root.zig"), .target = target, .optimize = optimize });
    native_gkr_root.addImport("stwo_core", core);
    native_gkr_root.addImport("stwo_cpu_backend", cpu_backend);
    native_gkr_root.addImport("stwo_prover_api", prover_api);
    native_gkr_root.addImport("interop_postcard", postcard);
    native_gkr_root.addImport("stwo_proof_wire", postcard.import_table.get("stwo_proof_wire") orelse @panic("missing wire"));
    native_gkr_root.addImport("stwo_prover_engine", prover);
    native_gkr_root.addImport("stwo_riscv_frontend", frontend);
    const native_gkr_filter = b.option([]const u8, "native-gkr-test-filter", "Run matching native GKR tests only");
    const native_gkr_tests = b.addTest(.{ .root_module = native_gkr_root, .filters = if (native_gkr_filter) |filter| &.{filter} else &.{} });
    b.step("test-native-gkr", "Test native GKR v1 and v2 bounded roster, codec, transcript and tamper corpus").dependOn(testDependency(b, native_gkr_tests, check_only, 0));
    const p2_native_root = b.createModule(.{ .root_source_file = b.path("rv64_poseidon2_native_test_root.zig"), .target = target, .optimize = optimize, .strip = false, .error_tracing = true });
    var p2_native_imports = native_gkr_root.import_table.iterator();
    while (p2_native_imports.next()) |entry| p2_native_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const p2_native_tests = b.addTest(.{ .root_module = p2_native_root, .filters = &.{"P2 native complete CPU fixture"} });
    b.step("test-poseidon2-native-cpu", "Prove and fresh-verify full RV64 CPU with explicit mixed P2 PCS/local-Blake GKR fixture profile").dependOn(testDependency(b, p2_native_tests, check_only, 0));
    const p2_receiver_root = b.createModule(.{ .root_source_file = b.path("rv64_poseidon2_native_fixture_main.zig"), .target = target, .optimize = optimize, .strip = false, .error_tracing = true });
    var p2_receiver_imports = native_gkr_root.import_table.iterator();
    while (p2_receiver_imports.next()) |entry| p2_receiver_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const p2_receiver = b.addExecutable(.{ .name = "rv64-p2-native-fixture", .root_module = p2_receiver_root });
    b.step("poseidon2-native-fixture", "Build independent full RV64 P2 native fixture receiver").dependOn(if (check_only) &p2_receiver.step else &b.addInstallArtifact(p2_receiver, .{}).step);
    const d2_root = b.createModule(.{ .root_source_file = b.path("rv64_d2_profile_test_root.zig"), .target = target, .optimize = optimize, .strip = false, .error_tracing = true });
    var d2_imports = native_gkr_root.import_table.iterator();
    while (d2_imports.next()) |entry| d2_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const d2_filter = b.option([]const u8, "d2-test-filter", "Run matching D2 runtime profile and actual CPU proof gates");
    const d2_tests = b.addTest(.{ .root_module = d2_root, .filters = if (d2_filter) |filter| &.{filter} else &.{} });
    b.step("test-d2-native", "Check explicit D2 runtime profile and fresh-receiver CPU proof without a GPU").dependOn(testDependency(b, d2_tests, check_only, 0));
    const truth_plan_root = b.createModule(.{ .root_source_file = b.path("rv64_truth_family_plan_test_root.zig"), .target = target, .optimize = optimize });
    var truth_plan_imports = native_gkr_root.import_table.iterator();
    while (truth_plan_imports.next()) |entry| truth_plan_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const truth_plan_tests = b.addTest(.{ .root_module = truth_plan_root, .filters = &.{"one truth per family"} });
    b.step("test-truth-family-plan", "Check opt-in one-truth-per-family source geometry and fail-closed capacity").dependOn(testDependency(b, truth_plan_tests, check_only, 0));
    const d2_circuit_root = b.createModule(.{ .root_source_file = b.path("rv64_d2_circuit_test_root.zig"), .target = target, .optimize = optimize, .strip = false, .error_tracing = true });
    var d2_circuit_imports = native_gkr_root.import_table.iterator();
    while (d2_circuit_imports.next()) |entry| d2_circuit_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    d2_circuit_root.addImport("stwo_circuit_frontend", circuit_frontend);
    const d2_circuit_tests = b.addTest(.{ .root_module = d2_circuit_root, .filters = &.{"D2 actual native CPU recursive"} });
    b.step("test-d2-circuit-census", "Construct and census actual native default/D2 CPU recursive verifier graphs").dependOn(testDependency(b, d2_circuit_tests, check_only, 0));
    const census_root = b.createModule(.{ .root_source_file = b.path("rv64_native_gkr_census_main.zig"), .target = target, .optimize = optimize });
    var census_imports = native_gkr_root.import_table.iterator();
    while (census_imports.next()) |entry| census_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const census = b.addExecutable(.{ .name = "rv64-native-gkr-census", .root_module = census_root });
    b.step("native-layout-census", "Build pure declaration/native-layout census without a production prover build").dependOn(&b.addInstallArtifact(census, .{}).step);
    const native_gkr_circuit_root = b.createModule(.{ .root_source_file = b.path("rv64_native_gkr_circuit_test_root.zig"), .target = target, .optimize = optimize });
    var native_gkr_imports = native_gkr_root.import_table.iterator();
    while (native_gkr_imports.next()) |entry| native_gkr_circuit_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    native_gkr_circuit_root.addImport("stwo_circuit_frontend", circuit_frontend);
    const native_gkr_circuit_tests = b.addTest(.{ .root_module = native_gkr_circuit_root, .filters = if (native_gkr_filter) |filter| &.{filter} else &.{} });
    b.step("test-native-gkr-circuit", "Test recursion-owned native GKR circuit and PCS statement adapters").dependOn(testDependency(b, native_gkr_circuit_tests, check_only, 0));

    const test_filter = b.option([]const u8, "test-filter", "Run only tests whose names contain this text");
    const tests = b.addTest(.{ .root_module = integration, .filters = if (test_filter) |filter| &.{filter} else &.{} });
    b.step("test", "Test the focused RISC-V CPU integration")
        .dependOn(testDependency(b, tests, check_only, 0));

    const secp_root = b.createModule(.{
        .root_source_file = b.path("secp256k1_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp_root.addImport("stwo_cpu_backend", cpu_backend);
    secp_root.addImport("stwo_riscv_frontend", frontend);
    secp_root.addImport("stwo_core", core);
    secp_root.addImport("stwo_prover_engine", prover);
    secp_root.addImport("secp256k1_proof_harness", frontend_dependency.module("secp256k1_proof_harness"));
    const secp_tests = b.addTest(.{ .root_module = secp_root });
    b.step("test-secp256k1-precompile-proof", "Prove and independently verify typed and canonical CSP ECDSA on CPU")
        .dependOn(testDependency(b, secp_tests, check_only, 0));

    const keccak_root = b.createModule(.{
        .root_source_file = b.path("keccakf_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccak_root.addImport("stwo_cpu_backend", cpu_backend);
    keccak_root.addImport("stwo_riscv_frontend", frontend);
    keccak_root.addImport("stwo_core", core);
    keccak_root.addImport("stwo_prover_engine", prover);
    keccak_root.addImport("keccakf_proof_harness", frontend_dependency.module("keccakf_proof_harness"));
    const keccak_tests = b.addTest(.{
        .root_module = keccak_root,
        .filters = &.{"Keccak-f typed shard and lookup tables prove and independently verify"},
    });
    b.step("test-keccakf-precompile-proof", "Prove and independently verify typed Keccak-f on CPU")
        .dependOn(testDependency(b, keccak_tests, check_only, 0));

    const segment_root = b.createModule(.{
        .root_source_file = b.path("segment_v2_native_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    segment_root.addImport("stwo_core", core);
    segment_root.addImport("stwo_artifact_store", artifact_store);
    segment_root.addImport("stwo_prover_engine", prover);
    segment_root.addImport("stwo_prover_api", prover_api);
    segment_root.addImport("stwo_cpu_backend", cpu_backend);
    segment_root.addImport("stwo_riscv_frontend", frontend);
    segment_root.addImport("interop_postcard", postcard);
    const segment_tests = b.addTest(.{
        .root_module = segment_root,
        .filters = &.{"native V2 proves and independently verifies real nonfinal and final segments"},
    });
    b.step("test-segment-v2-native-proof", "Prove and independently verify real nonfinal and final SegmentV2 shards")
        .dependOn(testDependency(b, segment_tests, check_only, 0));

    const universal_root = b.createModule(.{
        .root_source_file = b.path("universal_typed_component_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    universal_root.addImport("stwo_core", core);
    universal_root.addImport("stwo_prover_api", prover_api);
    universal_root.addImport("stwo_cpu_backend", cpu_backend);
    universal_root.addImport("stwo_riscv_frontend", frontend);
    universal_root.addImport("stwo_prover_engine", prover);
    const universal_tests = b.addTest(.{ .root_module = universal_root });
    b.step("test-universal-typed-proof", "Prove and independently verify the generic typed FRI adapter")
        .dependOn(testDependency(b, universal_tests, check_only, 3));

    // Generic SegmentV2 detached tools remain available for the qualified
    // continuation path. Ethereum block assembly is an archived experiment.
    const leaf_verifier_root = b.createModule(.{
        .root_source_file = b.path("../../frontends/riscv/leaf_verifier.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_verifier_root.addImport("stwo_core", core);
    leaf_verifier_root.addImport("interop_postcard", postcard);
    const leaf_verifier_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_verifier_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_verifier_runner.addImport("stwo_leaf_verifier", leaf_verifier_root);
    const leaf_verifier = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-verify",
        .root_module = leaf_verifier_runner,
    });
    b.step("build-recursive-segment-v2-detached-verifier", "Build the detached SegmentV2 leaf verifier")
        .dependOn(&b.addInstallArtifact(leaf_verifier, .{}).step);

    const parent_verifier_root = b.createModule(.{
        .root_source_file = b.path("../../frontends/riscv/parent_verifier.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_verifier_root.addImport("stwo_core", core);
    parent_verifier_root.addImport("interop_postcard", postcard);
    const parent_verifier_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_verifier_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_verifier_runner.addImport("stwo_parent_verifier", parent_verifier_root);
    const parent_verifier = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-parent-verify",
        .root_module = parent_verifier_runner,
    });
    b.step("build-recursive-segment-v2-detached-parent-verifier", "Build the detached SegmentV2 parent verifier")
        .dependOn(&b.addInstallArtifact(parent_verifier, .{}).step);

    const leaf_producer_root = b.addModule("stwo_riscv_detached_leaf_runner", .{
        .root_source_file = b.path("recursive_segment_v2_detached_leaf_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_producer_root.addImport("stwo_core", core);
    leaf_producer_root.addImport("stwo_cpu_backend", cpu_backend);
    leaf_producer_root.addImport("stwo_riscv_frontend", frontend);
    leaf_producer_root.addImport("stwo_prover_api", prover_api);
    leaf_producer_root.addImport("stwo_prover_engine", prover);
    leaf_producer_root.addImport("interop_postcard", postcard);
    const leaf_producer = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-leaf-prove",
        .root_module = leaf_producer_root,
    });
    b.step("build-recursive-segment-v2-detached-leaf-producer", "Build the detached SegmentV2 leaf producer")
        .dependOn(&b.addInstallArtifact(leaf_producer, .{}).step);

    const parent_producer_owner = b.addModule("stwo_riscv_detached_parent_producer", .{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_producer_owner.addImport("stwo_core", core);
    parent_producer_owner.addImport("stwo_cpu_backend", cpu_backend);
    parent_producer_owner.addImport("stwo_riscv_frontend", frontend);
    parent_producer_owner.addImport("stwo_prover_api", prover_api);
    parent_producer_owner.addImport("stwo_prover_engine", prover);
    parent_producer_owner.addImport("interop_postcard", postcard);
    const parent_producer_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_producer_runner.addImport("stwo_riscv_detached_parent_producer", parent_producer_owner);
    const parent_producer = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-parent-prove",
        .root_module = parent_producer_runner,
    });
    b.step("build-recursive-segment-v2-detached-parent-producer", "Build the detached SegmentV2 parent producer")
        .dependOn(&b.addInstallArtifact(parent_producer, .{}).step);
}

// Keep semantic checks independent of emitted binaries and test processes.
// Requesting a Run artifact requests code generation in Zig 0.15.2.
fn testDependency(b: *std.Build, tests: *std.Build.Step.Compile, check_only: bool, minimum: usize) *std.Build.Step {
    if (check_only) return &tests.step;
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;
    return if (minimum == 0) &run.step else TestCountFloor.add(b, run, minimum);
}

// Standalone package builds cannot import the repository build support.
const TestCountFloor = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    minimum: usize,

    fn add(b: *std.Build, run: *std.Build.Step.Run, minimum: usize) *std.Build.Step {
        const floor = b.allocator.create(TestCountFloor) catch @panic("out of memory");
        floor.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "stwo_riscv_cpu_integration test count floor",
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
