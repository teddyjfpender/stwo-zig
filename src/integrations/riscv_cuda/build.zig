const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const contracts = b.dependency(
        "stwo_backend_contracts",
        options,
    ).module("stwo_backend_contracts");
    const backend = b.dependency(
        "stwo_cuda_backend",
        options,
    ).module("stwo_cuda_backend");
    const frontend = b.dependency(
        "stwo_riscv_frontend",
        options,
    ).module("stwo_riscv_frontend");
    const circuit_cpu = b.dependency("stwo_circuit_cpu_integration", options).module("stwo_circuit_cpu_integration");
    const cpu_integration = b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration");
    // Only recursion-linked entry points reach these lazy imports. Native
    // resident production does not instantiate circuit construction/proving.
    cpu_integration.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    cpu_integration.addImport("stwo_cairo_frontend", circuit_cpu.import_table.get("stwo_cairo_frontend") orelse @panic("circuit native authority is missing recorded AIR types"));
    cpu_integration.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    // These two concrete native families share the package-owned wire module;
    // Zig must not instantiate the same proof-wire source twice in one binary.
    circuit_cpu.addImport("stwo_proof_wire", cpu_integration.import_table.get("stwo_proof_wire") orelse @panic("native CPU module is missing proof wire"));
    const integration = b.addModule("stwo_riscv_cuda_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_backend_contracts", contracts);
    integration.addImport("stwo_cuda_backend", backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    integration.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    integration.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    integration.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    integration.addImport("stwo_prover_api", cpu_integration.import_table.get("stwo_prover_api") orelse @panic("native CPU module is missing prover API"));
    integration.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    integration.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const router_root = b.createModule(.{ .root_source_file = b.path("rv64_router_test_root.zig"), .target = target, .optimize = optimize });
    router_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    router_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    router_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const router_tests = b.addTest(.{ .root_module = router_root });
    b.step("test-rv64-resident-router", "Test concrete multi-device RV64 routing and bounded custody without a GPU").dependOn(&b.addRunArtifact(router_tests).step);
    const pcs_geometry_root = b.createModule(.{ .root_source_file = b.path("rv64_pcs_geometry_test_root.zig"), .target = target, .optimize = optimize });
    pcs_geometry_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    pcs_geometry_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    pcs_geometry_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const pcs_geometry_tests = b.addTest(.{ .root_module = pcs_geometry_root });
    b.step("test-rv64-pcs-geometry", "Check bounded immutable PCS geometry and fresh request framing without a GPU").dependOn(&b.addRunArtifact(pcs_geometry_tests).step);
    const gkr_plan_root = b.createModule(.{ .root_source_file = b.path("rv64_gkr_plan_test_root.zig"), .target = target, .optimize = optimize });
    gkr_plan_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    gkr_plan_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    gkr_plan_root.addImport("stwo_cuda_backend", backend);
    const gkr_plan_tests = b.addTest(.{ .root_module = gkr_plan_root });
    b.step("test-rv64-gkr-plan", "Check consumed-tree GKR workspace custody without CUDA or a full prover build").dependOn(&b.addRunArtifact(gkr_plan_tests).step);
    const batch_test_root = b.createModule(.{ .root_source_file = b.path("rv64_batch_test_root.zig"), .target = target, .optimize = optimize });
    batch_test_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    batch_test_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    batch_test_root.addImport("stwo_cuda_backend", backend);
    const batch_tests = b.addTest(.{ .root_module = batch_test_root });
    b.step("test-rv64-batch-plan", "Test mixed-height batch enqueue control without CUDA or a full prover build").dependOn(&b.addRunArtifact(batch_tests).step);
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
    const test_step = b.step(
        "test",
        "Run host-independent RISC-V CUDA integration contract tests",
    );
    test_step.dependOn(&tests.step);
    const prefix_tests = b.addExecutable(.{
        .name = "rv64-prefix-bank-tests",
        .root_module = b.createModule(.{ .target = b.graph.host, .optimize = optimize }),
    });
    prefix_tests.addCSourceFile(.{ .file = b.path("../../backends/cuda/native/rv64/prefix_banks_test.cpp"), .flags = &.{"-std=c++17"} });
    prefix_tests.linkLibC();
    prefix_tests.linkLibCpp();
    const run_prefix_tests = b.addRunArtifact(prefix_tests);
    b.step("test-prefix-banks", "Check alternating Merkle prefix workspace geometry without a GPU").dependOn(&run_prefix_tests.step);
    test_step.dependOn(&run_prefix_tests.step);

    const numerical_root = b.createModule(.{
        .root_source_file = b.path("rv64_numerical_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    numerical_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    numerical_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const numerical = b.addTest(.{ .root_module = numerical_root });
    numerical.addCSourceFile(.{ .file = b.path("../../../tests/cuda/rv64/numerical_bridge.cpp"), .flags = &.{"-std=c++17"} });
    numerical.addIncludePath(b.path("../../../tests/cuda/rv64/host_include"));
    numerical.addIncludePath(b.path("../../backends/cuda/native"));
    numerical.linkLibCpp();
    const numerical_step = b.step("test-rv64-numerical", "Check CUDA host arithmetic against native OM31 and GKR");
    const run_numerical = b.addRunArtifact(numerical);
    numerical_step.dependOn(&run_numerical.step);
    test_step.dependOn(&run_numerical.step);
    const fixture_root = b.createModule(.{
        .root_source_file = b.path("rv64_composition_fixture_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fixture_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    fixture_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    fixture_root.addImport("stwo_riscv_frontend", frontend);
    fixture_root.addImport("stwo_cuda_backend", backend);
    const fixture = b.addExecutable(.{ .name = "rv64-composition-fixtures", .root_module = fixture_root });
    const run_fixture = b.addRunArtifact(fixture);
    if (b.args) |args| run_fixture.addArgs(args);
    b.step("rv64-composition-fixtures", "Export OM31 CUDA equations and native numerical fixtures").dependOn(&run_fixture.step);
    const batch_root = b.createModule(.{
        .root_source_file = b.path("rv64_batch_fixture_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    batch_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    batch_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const batch_fixture = b.addExecutable(.{ .name = "rv64-batch-fixtures", .root_module = batch_root });
    const run_batch = b.addRunArtifact(batch_fixture);
    if (b.args) |args| run_batch.addArgs(args);
    b.step("rv64-batch-fixtures", "Export native mixed-height OM31 sumcheck fixtures").dependOn(&run_batch.step);
    const gkr_root = b.createModule(.{
        .root_source_file = b.path("rv64_gkr_fixture_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    gkr_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    gkr_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    gkr_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const gkr_fixture = b.addExecutable(.{ .name = "rv64-gkr-fixtures", .root_module = gkr_root });
    const run_gkr = b.addRunArtifact(gkr_fixture);
    if (b.args) |args| run_gkr.addArgs(args);
    b.step("rv64-gkr-fixtures", "Export full native OM31 GKR proof fixtures").dependOn(&run_gkr.step);
    const projection_root = b.createModule(.{ .root_source_file = b.path("rv64_projection_fixture_main.zig"), .target = target, .optimize = optimize });
    projection_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    projection_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    projection_root.addImport("stwo_riscv_frontend", frontend);
    projection_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    projection_root.addImport("stwo_cuda_backend", backend);
    const projection_fixture = b.addExecutable(.{ .name = "rv64-projection-fixtures", .root_module = projection_root });
    const run_projection = b.addRunArtifact(projection_fixture);
    if (b.args) |args| run_projection.addArgs(args);
    b.step("rv64-projection-fixtures", "Export native source-column projection fixtures").dependOn(&run_projection.step);
    const joined_root = b.createModule(.{
        .root_source_file = b.path("rv64_joined_fixture_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    joined_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    joined_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    joined_root.addImport("stwo_riscv_frontend", frontend);
    joined_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    joined_root.addImport("stwo_cuda_backend", backend);
    joined_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    joined_root.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    joined_root.addImport("stwo_prover_api", cpu_integration.import_table.get("stwo_prover_api") orelse @panic("missing native prover API"));
    const joined_fixture = b.addExecutable(.{ .name = "rv64-joined-fixtures", .root_module = joined_root });
    // CUDA's glibc/libstdc++ TLS requires the system dynamic loader.
    joined_fixture.linkLibC();
    b.step("build-rv64-joined-tool", "Build existing joined AIR tool without running it").dependOn(&b.addInstallArtifact(joined_fixture, .{}).step);
    const run_joined = b.addRunArtifact(joined_fixture);
    if (b.args) |args| run_joined.addArgs(args);
    b.step("rv64-joined-fixtures", "Export complete joined native AIR fixtures and cold CUDA kernels").dependOn(&run_joined.step);
    const deep_root = b.createModule(.{ .root_source_file = b.path("rv64_deep_fixture_main.zig"), .target = target, .optimize = optimize });
    deep_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    deep_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const deep_fixture = b.addExecutable(.{ .name = "rv64-deep-fixtures", .root_module = deep_root });
    const run_deep = b.addRunArtifact(deep_fixture);
    if (b.args) |args| run_deep.addArgs(args);
    b.step("rv64-deep-fixtures", "Export native OM31 compact coefficient DEEP fixtures").dependOn(&run_deep.step);
    const samples_root = b.createModule(.{ .root_source_file = b.path("rv64_samples_fixture_main.zig"), .target = target, .optimize = optimize });
    samples_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    samples_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const samples_fixture = b.addExecutable(.{ .name = "rv64-samples-fixtures", .root_module = samples_root });
    const run_samples = b.addRunArtifact(samples_fixture);
    if (b.args) |args| run_samples.addArgs(args);
    b.step("rv64-samples-fixtures", "Export native OM31 transcript/point/polynomial sampling fixtures").dependOn(&run_samples.step);
    const fri_root = b.createModule(.{ .root_source_file = b.path("rv64_fri_fixture_main.zig"), .target = target, .optimize = optimize });
    fri_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    fri_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    fri_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const fri_fixture = b.addExecutable(.{ .name = "rv64-fri-fixtures", .root_module = fri_root });
    b.step("build-rv64-fri-tool", "Build the independent native FRI fixture receiver").dependOn(&b.addInstallArtifact(fri_fixture, .{}).step);
    const run_fri = b.addRunArtifact(fri_fixture);
    if (b.args) |args| run_fri.addArgs(args);
    b.step("rv64-fri-fixtures", "Export native FRI fixtures or verify GPU compact proof readback").dependOn(&run_fri.step);
    const arith_witness_root = b.createModule(.{ .root_source_file = b.path("rv64_arith256_witness_fixture_main.zig"), .target = target, .optimize = optimize });
    arith_witness_root.addImport("stwo_riscv_frontend", frontend);
    const arith_witness_fixture = b.addExecutable(.{ .name = "rv64-arith256-witness-fixtures", .root_module = arith_witness_root });
    const run_arith_witness = b.addRunArtifact(arith_witness_fixture);
    if (b.args) |args| run_arith_witness.addArgs(args);
    b.step("rv64-arith256-witness-fixtures", "Export compact arithmetic service inputs and independent native MAIN digests").dependOn(&run_arith_witness.step);
    const sha_witness_root = b.createModule(.{ .root_source_file = b.path("rv64_sha256_witness_fixture_main.zig"), .target = target, .optimize = optimize });
    sha_witness_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    sha_witness_root.addImport("stwo_riscv_frontend", frontend);
    const sha_witness_fixture = b.addExecutable(.{ .name = "rv64-sha256-witness-fixtures", .root_module = sha_witness_root });
    const run_sha_witness = b.addRunArtifact(sha_witness_fixture);
    if (b.args) |args| run_sha_witness.addArgs(args);
    b.step("rv64-sha256-witness-fixtures", "Export compact SHA service inputs and native MAIN digests").dependOn(&run_sha_witness.step);
    const service_root = b.createModule(.{ .root_source_file = b.path("rv64_service_witness_fixture_main.zig"), .target = target, .optimize = optimize });
    service_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    service_root.addImport("stwo_riscv_frontend", frontend);
    service_root.addImport("stwo_cuda_backend", backend);
    service_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const service_fixture = b.addExecutable(.{ .name = "rv64-service-witness-fixtures", .root_module = service_root });
    const run_service = b.addRunArtifact(service_fixture);
    if (b.args) |args| run_service.addArgs(args);
    b.step("rv64-service-witness-fixtures", "Export compact bulk/sponge records and independent native MAIN/range oracles").dependOn(&run_service.step);
    const global_root = b.createModule(.{ .root_source_file = b.path("rv64_global_fixture_main.zig"), .target = target, .optimize = optimize });
    global_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    global_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    global_root.addImport("stwo_riscv_frontend", frontend);
    global_root.addImport("stwo_cuda_backend", backend);
    global_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const global_fixture = b.addExecutable(.{ .name = "rv64-global-fixtures", .root_module = global_root });
    const run_global = b.addRunArtifact(global_fixture);
    if (b.args) |args| run_global.addArgs(args);
    b.step("rv64-global-fixtures", "Export native global tuple projections and classic interaction witnesses").dependOn(&run_global.step);
    const closure_root = b.createModule(.{ .root_source_file = b.path("rv64_closure_fixture_main.zig"), .target = target, .optimize = optimize });
    closure_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    closure_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const closure_fixture = b.addExecutable(.{ .name = "rv64-closure-fixtures", .root_module = closure_root });
    const run_closure = b.addRunArtifact(closure_fixture);
    if (b.args) |args| run_closure.addArgs(args);
    b.step("rv64-closure-fixtures", "Export native local GKR and manifest-claim closure fixtures").dependOn(&run_closure.step);
    const trace_root = b.createModule(.{ .root_source_file = b.path("rv64_trace_fixture_main.zig"), .target = target, .optimize = optimize });
    trace_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    trace_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const trace_fixture = b.addExecutable(.{ .name = "rv64-trace-fixtures", .root_module = trace_root });
    const run_trace = b.addRunArtifact(trace_fixture);
    if (b.args) |args| run_trace.addArgs(args);
    b.step("rv64-trace-fixtures", "Export native lifted PCS trees or freshly verify GPU openings").dependOn(&run_trace.step);
    b.step("build-rv64-trace-tool", "Build independent native lifted trace opening receiver").dependOn(&b.addInstallArtifact(trace_fixture, .{}).step);
    const pcs_root = b.createModule(.{ .root_source_file = b.path("rv64_pcs_fixture_main.zig"), .target = target, .optimize = optimize });
    pcs_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    pcs_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    pcs_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const pcs_fixture = b.addExecutable(.{ .name = "rv64-pcs-fixtures", .root_module = pcs_root });
    const run_pcs = b.addRunArtifact(pcs_fixture);
    if (b.args) |args| run_pcs.addArgs(args);
    b.step("rv64-pcs-fixtures", "Export native complete PCS oracle or verify resident GPU proof").dependOn(&run_pcs.step);
    b.step("build-rv64-pcs-tool", "Build independent native complete PCS receiver").dependOn(&b.addInstallArtifact(pcs_fixture, .{}).step);
    const masked_pcs_root = b.createModule(.{ .root_source_file = b.path("rv64_pcs_masks_fixture_main.zig"), .target = target, .optimize = optimize });
    masked_pcs_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    masked_pcs_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    masked_pcs_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const masked_pcs_fixture = b.addExecutable(.{ .name = "rv64-masked-pcs-fixtures", .root_module = masked_pcs_root });
    const run_masked_pcs = b.addRunArtifact(masked_pcs_fixture);
    if (b.args) |args| run_masked_pcs.addArgs(args);
    b.step("rv64-masked-pcs-fixtures", "Export native heterogeneous PCS masks or verify resident GPU proof").dependOn(&run_masked_pcs.step);
    b.step("build-rv64-masked-pcs-tool", "Build independent native heterogeneous PCS receiver").dependOn(&b.addInstallArtifact(masked_pcs_fixture, .{}).step);
    const split_root = b.createModule(.{ .root_source_file = b.path("rv64_composition_split_fixture_main.zig"), .target = target, .optimize = optimize });
    split_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    split_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const split_fixture = b.addExecutable(.{ .name = "rv64-composition-split-fixtures", .root_module = split_root });
    const run_split = b.addRunArtifact(split_fixture);
    if (b.args) |args| run_split.addArgs(args);
    b.step("rv64-composition-split-fixtures", "Export native four/eight-coordinate composition split oracle").dependOn(&run_split.step);
    const dword_root = b.createModule(.{ .root_source_file = b.path("rv64_ls_dword_fixture_main.zig"), .target = target, .optimize = optimize });
    dword_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    dword_root.addImport("stwo_riscv_frontend", b.dependency("stwo_riscv_frontend", options).module("stwo_riscv_frontend"));
    const dword_fixture = b.addExecutable(.{ .name = "rv64-ls-dword-fixtures", .root_module = dword_root });
    const run_dword = b.addRunArtifact(dword_fixture);
    if (b.args) |args| run_dword.addArgs(args);
    b.step("rv64-ls-dword-fixtures", "Export native compact-event LS-D64 witness oracle").dependOn(&run_dword.step);
    const cpu_witness_root = b.createModule(.{ .root_source_file = b.path("rv64_cpu_witness_fixture_main.zig"), .target = target, .optimize = optimize });
    cpu_witness_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    cpu_witness_root.addImport("stwo_riscv_frontend", frontend);
    cpu_witness_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const cpu_witness_fixture = b.addExecutable(.{ .name = "rv64-cpu-witness-fixtures", .root_module = cpu_witness_root });
    const run_cpu_witness = b.addRunArtifact(cpu_witness_fixture);
    if (b.args) |args| run_cpu_witness.addArgs(args);
    b.step("rv64-cpu-witness-fixtures", "Export native compact CPU formatting and histogram oracle").dependOn(&run_cpu_witness.step);
    const family_root = b.createModule(.{ .root_source_file = b.path("rv64_family_witness_fixture_main.zig"), .target = target, .optimize = optimize });
    family_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    family_root.addImport("stwo_riscv_frontend", frontend);
    family_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    const family_fixture = b.addExecutable(.{ .name = "rv64-family-witness-fixtures", .root_module = family_root });
    const run_family = b.addRunArtifact(family_fixture);
    if (b.args) |args| run_family.addArgs(args);
    b.step("rv64-family-witness-fixtures", "Export native compact family MAIN and ledger oracle").dependOn(&run_family.step);
    const binding_root = b.createModule(.{
        .root_source_file = b.path("rv64_binding_check_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const hybrid_root = b.createModule(.{ .root_source_file = b.path("rv64_hybrid_ethereum_main.zig"), .target = target, .optimize = optimize });
    hybrid_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    hybrid_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    hybrid_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    hybrid_root.addImport("stwo_cuda_backend", backend);
    hybrid_root.addImport("stwo_riscv_frontend", frontend);
    const hybrid = b.addExecutable(.{ .name = "rv64-word16-ethereum-gpu", .root_module = hybrid_root });
    hybrid.linkLibC();
    const resident_check = b.addExecutable(.{ .name = "rv64-ethereum-resident-check", .root_module = hybrid_root });
    resident_check.linkLibC();
    b.step("check-rv64-ethereum-gpu", "Type-check the production GPU route without emitting a binary").dependOn(&resident_check.step);
    b.step("build-rv64-ethereum-gpu", "Build real Ethereum hybrid producer with explicit GPU PCS offload").dependOn(&b.addInstallArtifact(hybrid, .{}).step);
    const outer_root = b.createModule(.{ .root_source_file = b.path("rv64_outer_recursion_main.zig"), .target = target, .optimize = optimize });
    outer_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    outer_root.addImport("stwo_prover_api", cpu_integration.import_table.get("stwo_prover_api").?);
    outer_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    outer_root.addImport("stwo_riscv_cpu_integration", cpu_integration);
    outer_root.addImport("stwo_riscv_frontend", frontend);
    outer_root.addImport("stwo_cuda_backend", backend);
    outer_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    outer_root.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    const ready_root = b.createModule(.{ .root_source_file = b.path("rv64_recursion_ready_test_root.zig"), .target = target, .optimize = optimize });
    ready_root.addImport("stwo_riscv_cpu_integration", cpu_integration);
    ready_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const ready_tests = b.addTest(.{ .root_module = ready_root });
    const ready_step = b.step("test-rv64-recursion-ready", "Force ready API typing and test threaded custody, durable publication and stack budgets without a GPU");
    ready_step.dependOn(&b.addRunArtifact(ready_tests).step);
    for ([_][]const u8{ "ready_dag.zig", "publication.zig" }) |source| {
        const scheduler_root = b.createModule(.{ .root_source_file = b.path(b.fmt("../riscv_cpu/rv64_recursion/om31_native/{s}", .{source})), .target = target, .optimize = optimize });
        ready_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = scheduler_root })).step);
    }
    const outer = b.addExecutable(.{ .name = "rv64-word16-ethereum-gpu-recursion", .root_module = outer_root });
    outer.linkLibC();
    b.step("build-rv64-ethereum-gpu-recursion", "Build explicit CUDA native-OM31 outer recursion, no CPU fallback").dependOn(&b.addInstallArtifact(outer, .{}).step);
    const outer_check = b.addExecutable(.{ .name = "rv64-outer-gpu-check", .root_module = outer_root });
    outer_check.linkLibC();
    b.step("check-rv64-ethereum-gpu-recursion", "Type-check CUDA outer recursion without a GPU or binary output").dependOn(&outer_check.step);

    // CPU-only independent receiver shares the exact authority loader without
    // linking or initializing any CUDA context, including on restore.
    const receiver_root = b.createModule(.{ .root_source_file = b.path("rv64_recursion_receiver_main.zig"), .target = target, .optimize = optimize });
    receiver_root.addImport("stwo_riscv_cpu_integration", cpu_integration);
    const receiver = b.addExecutable(.{ .name = "rv64-word16-ethereum-recursion-receiver", .root_module = receiver_root });
    receiver.linkLibC();
    b.step("build-rv64-ethereum-recursion-receiver", "Build independent CPU-only current OM31 recursion receiver").dependOn(&b.addInstallArtifact(receiver, .{}).step);
    const receiver_check = b.addExecutable(.{ .name = "rv64-recursion-receiver-check", .root_module = receiver_root });
    receiver_check.linkLibC();
    b.step("check-rv64-ethereum-recursion-receiver", "Type-check independent CPU-only recursion receiver without emitting a binary").dependOn(&receiver_check.step);

    const combined_root = b.createModule(.{ .root_source_file = b.path("rv64_combined_ethereum_main.zig"), .target = target, .optimize = optimize });
    combined_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    combined_root.addImport("stwo_prover_api", cpu_integration.import_table.get("stwo_prover_api").?);
    combined_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    combined_root.addImport("stwo_riscv_cpu_integration", cpu_integration);
    combined_root.addImport("stwo_riscv_frontend", frontend);
    combined_root.addImport("stwo_cuda_backend", backend);
    combined_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    combined_root.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    const combined = b.addExecutable(.{ .name = "rv64-word16-ethereum-gpu-combined", .root_module = combined_root });
    combined.linkLibC();
    b.step("build-rv64-ethereum-gpu-combined", "Build one-process native GPU proving and GPU OM31 recursion").dependOn(&b.addInstallArtifact(combined, .{}).step);
    const combined_check = b.addExecutable(.{ .name = "rv64-combined-gpu-check", .root_module = combined_root });
    combined_check.linkLibC();
    b.step("check-rv64-ethereum-gpu-combined", "Type-check combined GPU proving and recursion without emitting a binary").dependOn(&combined_check.step);

    binding_root.addImport("stwo_cuda_backend", backend);
    binding_root.addImport("stwo_riscv_frontend", frontend);
    const binding_object = b.addObject(.{ .name = "rv64-cuda-binding-check", .root_module = binding_root });
    binding_object.linkLibC();
    const binding_step = b.step("check-rv64-native-bindings", "Compile real-context RV64 CUDA FFI without requiring a GPU");
    binding_step.dependOn(&binding_object.step);
    test_step.dependOn(&binding_object.step);
}
