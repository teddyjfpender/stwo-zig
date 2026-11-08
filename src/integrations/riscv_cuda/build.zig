const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const check_only = b.option(bool, "check-only", "Check focused job roots without executing tests") orelse false;
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
    const native_gkr_root = b.createModule(.{ .root_source_file = b.path("rv64_native_gkr_codegen_test_root.zig"), .target = target, .optimize = optimize, .strip = true });
    for ([_][]const u8{ "stwo_core", "stwo_prover_engine", "stwo_riscv_frontend", "stwo_riscv_cpu_integration", "stwo_cuda_backend", "stwo_circuit_frontend" }) |name| native_gkr_root.addImport(name, integration.import_table.get(name) orelse @panic("missing native GKR codegen dependency"));
    const native_gkr_tests = b.addTest(.{ .root_module = native_gkr_root });
    native_gkr_tests.linkLibC();
    b.step("test-native-gkr-codegen", "Check native raw source and reduced AIR against source authority").dependOn(&b.addRunArtifact(native_gkr_tests).step);

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
    gkr_plan_root.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    const gkr_plan_tests = b.addTest(.{ .root_module = gkr_plan_root });
    gkr_plan_tests.linkLibC();
    b.step("test-rv64-gkr-plan", "Check consumed-tree GKR workspace custody without CUDA or a full prover build").dependOn(&b.addRunArtifact(gkr_plan_tests).step);
    // M8 job runtime (rv64/jobs): host tests without a GPU. Runs from this
    // directory so the sync lint can read the job sources.
    const jobs_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_test_root.zig"), .target = target, .optimize = optimize });
    jobs_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    const jobs_tests = b.addTest(.{ .root_module = jobs_root });
    const jobs_run = jobTestStep(b, jobs_tests, check_only);
    const jobs_step = b.step("test-rv64-jobs", "Test the M8 job runtime contract, worker pipeline, channel parity model, slab, scheduler and sync lint without a GPU");
    jobs_step.dependOn(jobs_run);
    b.step("test-rv64-jobs-runtime", "Test job resources, worker, driver and lifecycle without the native/truth binaries").dependOn(jobs_run);
    const recursion_jobs_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_recursion_test_root.zig"), .target = target, .optimize = optimize });
    recursion_jobs_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    b.step("test-rv64-jobs-recursion", "Test installed recursion classes and request job custody without a GPU").dependOn(jobTestStep(b, b.addTest(.{ .root_module = recursion_jobs_root }), check_only));
    const resource_root = b.createModule(.{ .root_source_file = b.path("rv64_resources_test_root.zig"), .target = target, .optimize = optimize });
    b.step("test-rv64-resources", "Test checked job resources and the two-sided arena without a prover or GPU").dependOn(jobTestStep(b, b.addTest(.{ .root_module = resource_root }), check_only));
    // native-job: rv64/jobs/native_*.zig tests in their own binary (they reuse the legacy PCS framing and
    // decoder through stwo_riscv_cpu_integration, which must not share a binary with rv64_ready_dag).
    const jobs_native_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_native_test_root.zig"), .target = target, .optimize = optimize });
    jobs_native_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    jobs_native_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    jobs_native_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    // native-producers: the local GKR job reuses rv64/gkr*.zig (stwo_cuda_backend runtime slices, projection catalogue).
    jobs_native_root.addImport("stwo_cuda_backend", backend);
    jobs_native_root.addImport("stwo_riscv_frontend", frontend);
    const jobs_native_run = jobTestStep(b, b.addTest(.{ .root_module = jobs_native_root }), check_only);
    jobs_step.dependOn(jobs_native_run);
    b.step("test-rv64-jobs-native", "Test native jobs and codecs without building the combined prover").dependOn(jobs_native_run);
    const gkr_wire_root = b.createModule(.{ .root_source_file = b.path("rv64_gkr_wire_test_root.zig"), .target = target, .optimize = optimize });
    gkr_wire_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    gkr_wire_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    gkr_wire_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    gkr_wire_root.addImport("stwo_cuda_backend", backend);
    gkr_wire_root.addImport("stwo_riscv_frontend", frontend);
    gkr_wire_root.addImport("stwo_circuit_cpu_integration", b.dependency("stwo_circuit_cpu_integration", options).module("stwo_circuit_cpu_integration"));
    const gkr_wire_run = b.addRunArtifact(b.addTest(.{ .root_module = gkr_wire_root }));
    gkr_wire_run.setCwd(b.path("."));
    b.step("test-rv64-local-gkr-wire", "Compare the canonical local-GKR receipt and wire codecs (optional two-GPU parity)").dependOn(&gkr_wire_run.step);
    // r-truth (recursion): GPU-native TruthJob + device seed fill host tests
    // (rv64/jobs/truth_*.zig, outer_seed_*.zig); same imports as the native root.
    const jobs_truth_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_truth_test_root.zig"), .target = target, .optimize = optimize });
    jobs_truth_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    jobs_truth_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    jobs_truth_root.addImport("stwo_riscv_cpu_integration", b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration"));
    jobs_truth_root.addImport("stwo_cuda_backend", backend);
    jobs_truth_root.addImport("stwo_riscv_frontend", frontend);
    const jobs_truth_run = jobTestStep(b, b.addTest(.{ .root_module = jobs_truth_root }), check_only);
    jobs_step.dependOn(jobs_truth_run);
    b.step("test-rv64-jobs-truth", "Test the M8 GPU-native TruthJob plan, challenge scripts, parameter programs and seed programs without a GPU").dependOn(jobs_truth_run);
    const jobs_sched_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_sched_test_root.zig"), .target = target, .optimize = optimize });
    jobs_sched_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    jobs_sched_root.addImport("rv64_ready_dag", b.createModule(.{ .root_source_file = b.path("../riscv_cpu/rv64_recursion/om31_native/ready_dag.zig"), .target = target, .optimize = optimize }));
    jobs_step.dependOn(jobTestStep(b, b.addTest(.{ .root_module = jobs_sched_root }), check_only));
    const jobs_parity_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_parity_main.zig"), .target = target, .optimize = optimize });
    jobs_parity_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    jobs_parity_root.addImport("rv64_ready_dag", b.createModule(.{ .root_source_file = b.path("../riscv_cpu/rv64_recursion/om31_native/ready_dag.zig"), .target = target, .optimize = optimize }));
    const jobs_parity = b.addExecutable(.{ .name = "rv64-jobs-channel-parity", .root_module = jobs_parity_root });
    jobs_parity.linkLibC();
    b.step("build-rv64-jobs-parity", "Build the M8 job runtime GPU channel parity harness (pod)").dependOn(&b.addInstallArtifact(jobs_parity, .{}).step);
    // M8 outer-job (rv64/jobs/outer_*): plan, enqueue-only trace commit, graph
    // cache policy and staged image, host tests without a GPU.
    const jobs_outer_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_outer_test_root.zig"), .target = target, .optimize = optimize });
    jobs_outer_root.addImport("stwo_cuda_backend", backend);
    const jobs_outer_tests = b.addTest(.{ .root_module = jobs_outer_root });
    jobs_outer_tests.linkLibC();
    b.step("test-rv64-jobs-outer", "Test the M8 OuterNodeJob class plan, enqueue-only trace commit, graph cache and staged image without a GPU").dependOn(jobTestStep(b, jobs_outer_tests, check_only));
    const jobs_node_root = b.createModule(.{ .root_source_file = b.path("rv64_jobs_node_test_root.zig"), .target = target, .optimize = optimize });
    for ([_][]const u8{ "stwo_core", "stwo_prover_engine", "stwo_riscv_frontend", "stwo_riscv_cpu_integration", "stwo_cuda_backend", "stwo_circuit_cpu_integration" }) |name| jobs_node_root.addImport(name, integration.import_table.get(name) orelse @panic("missing node contract dependency"));
    const jobs_node_tests = b.addTest(.{ .root_module = jobs_node_root });
    jobs_node_tests.linkLibC();
    const jobs_node_step = jobTestStep(b, jobs_node_tests, check_only);
    b.step("test-rv64-jobs-node", "Test host-observed node result contracts; no GPU or full block proof").dependOn(jobs_node_step);
    jobs_step.dependOn(jobs_node_step);
    const batch_test_root = b.createModule(.{ .root_source_file = b.path("rv64_batch_test_root.zig"), .target = target, .optimize = optimize });
    batch_test_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    batch_test_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    batch_test_root.addImport("stwo_cuda_backend", backend);
    const batch_tests = b.addTest(.{ .root_module = batch_test_root });
    batch_tests.linkLibC();
    b.step("test-rv64-batch-plan", "Test mixed-height batch enqueue control without CUDA or a full prover build").dependOn(&b.addRunArtifact(batch_tests).step);
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
    const prestage_root = b.createModule(.{ .root_source_file = b.path("rv64_cpu_prestage_test_root.zig"), .target = target, .optimize = optimize, .strip = true });
    for ([_][]const u8{ "stwo_core", "stwo_riscv_frontend", "stwo_riscv_cpu_integration", "stwo_cuda_backend", "stwo_prover_api", "stwo_prover_engine" }) |name| prestage_root.addImport(name, integration.import_table.get(name) orelse @panic("missing CPU prestage dependency"));
    const prestage_tests = b.addTest(.{ .root_module = prestage_root });
    prestage_tests.linkLibC();
    b.step("test-rv64-cpu-prestage", "Check private CPU witness staging input and ownership contracts").dependOn(&b.addRunArtifact(prestage_tests).step);
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

    const stream_plan_tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("rv64/trace_stream_plan.zig"), .target = b.graph.host, .optimize = optimize }) });
    const run_stream_plan_tests = b.addRunArtifact(stream_plan_tests);
    b.step("test-trace-stream-plan", "Check chunked LDE->Merkle streaming plans and schedule-independent absorption without a GPU").dependOn(&run_stream_plan_tests.step);
    test_step.dependOn(&run_stream_plan_tests.step);
    const idle_cache_tests = b.addExecutable(.{
        .name = "rv64-pcs-idle-cache-tests",
        .root_module = b.createModule(.{ .target = b.graph.host, .optimize = optimize }),
    });
    idle_cache_tests.addCSourceFile(.{ .file = b.path("../../backends/cuda/native/rv64/pcs_idle_cache_test.cpp"), .flags = &.{ "-std=c++17", "-Wall", "-Wextra", "-Werror" } });
    idle_cache_tests.linkLibC();
    idle_cache_tests.linkLibCpp();
    b.step("test-pcs-idle-cache", "Check optional upper PCS cache parsing, scoped phase custody and failure ledgers without CUDA").dependOn(&b.addRunArtifact(idle_cache_tests).step);

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
    b.step("build-rv64-projection-tool", "Build the projection AOT catalogue generator without running it (catalogue gate)").dependOn(&b.addInstallArtifact(projection_fixture, .{}).step);
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
    b.step("build-rv64-global-tool", "Build the global AOT catalogue generator without running it (catalogue gate)").dependOn(&b.addInstallArtifact(global_fixture, .{}).step);
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
    ready_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    ready_root.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
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
    // M8 outer-job parity fixture (pod): legacy controller vs OuterNodeJob prefix.
    const outer_job_root = b.createModule(.{ .root_source_file = b.path("rv64_m8_outer_job_main.zig"), .target = target, .optimize = optimize });
    for ([_][]const u8{ "stwo_core", "stwo_prover_api", "stwo_prover_engine", "stwo_riscv_cpu_integration", "stwo_riscv_frontend", "stwo_cuda_backend", "stwo_circuit_cpu_integration", "stwo_circuit_frontend" }) |name| outer_job_root.addImport(name, outer_root.import_table.get(name) orelse @panic("missing outer job fixture dependency"));
    const outer_job = b.addExecutable(.{ .name = "rv64-m8-outer-job-fixture", .root_module = outer_job_root });
    outer_job.linkLibC();
    b.step("build-rv64-m8-outer-job-fixture", "Build the M8 OuterNodeJob parity fixture (legacy controller vs job prefix)").dependOn(&b.addInstallArtifact(outer_job, .{}).step);
    const outer_check = b.addExecutable(.{ .name = "rv64-outer-gpu-check", .root_module = outer_root });
    outer_check.linkLibC();
    b.step("check-rv64-ethereum-gpu-recursion", "Type-check CUDA outer recursion without a GPU or binary output").dependOn(&outer_check.step);

    const hybrid_fixture_root = b.createModule(.{ .root_source_file = b.path("rv64_hybrid_fixture_main.zig"), .target = target, .optimize = optimize });
    hybrid_fixture_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    hybrid_fixture_root.addImport("stwo_prover_api", cpu_integration.import_table.get("stwo_prover_api").?);
    hybrid_fixture_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    hybrid_fixture_root.addImport("stwo_riscv_cpu_integration", cpu_integration);
    hybrid_fixture_root.addImport("stwo_riscv_frontend", frontend);
    hybrid_fixture_root.addImport("stwo_cuda_backend", backend);
    hybrid_fixture_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    hybrid_fixture_root.addImport("stwo_circuit_frontend", b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend"));
    const hybrid_fixture = b.addExecutable(.{ .name = "rv64-outer-hybrid-fixtures", .root_module = hybrid_fixture_root });
    hybrid_fixture.linkLibC();
    b.step("build-rv64-outer-hybrid-fixtures", "Build explicit hybrid CUDA fixture and independent CPU receiver").dependOn(&b.addInstallArtifact(hybrid_fixture, .{}).step);
    const typed_pair_root = b.createModule(.{ .root_source_file = b.path("rv64_hybrid_typed_pair_main.zig"), .target = target, .optimize = optimize });
    var typed_imports = hybrid_fixture_root.import_table.iterator();
    while (typed_imports.next()) |entry| typed_pair_root.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const typed_pair = b.addExecutable(.{ .name = "rv64-outer-hybrid-typed-pair", .root_module = typed_pair_root });
    typed_pair.linkLibC();
    b.step("build-rv64-outer-hybrid-typed-pair", "Build scoped hybrid typed-fold proof and pinned root-only receiver fixture").dependOn(&b.addInstallArtifact(typed_pair, .{}).step);

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
    // M8 native-producers real-block parity harness (pod): legacy native pipeline with a
    // wrapped local-GKR stage that re-proves every segment as a job and compares.
    const native_parity_root = b.createModule(.{ .root_source_file = b.path("rv64_m8_native_parity_main.zig"), .target = target, .optimize = optimize });
    for ([_][]const u8{ "stwo_core", "stwo_prover_api", "stwo_prover_engine", "stwo_riscv_cpu_integration", "stwo_riscv_frontend", "stwo_cuda_backend", "stwo_circuit_cpu_integration", "stwo_circuit_frontend" }) |name| native_parity_root.addImport(name, combined_root.import_table.get(name) orelse @panic("missing native parity dependency"));
    const native_parity = b.addExecutable(.{ .name = "rv64-m8-native-parity", .root_module = native_parity_root });
    native_parity.linkLibC();
    b.step("build-rv64-m8-native-parity", "Build the M8 native-producers real-block parity harness (legacy native + job local GKR)").dependOn(&b.addInstallArtifact(native_parity, .{}).step);
    // r-truth (recursion): GPU-native TruthJob real-block parity harness.
    const truth_parity_root = b.createModule(.{ .root_source_file = b.path("rv64_m8_truth_parity_main.zig"), .target = target, .optimize = optimize });
    for ([_][]const u8{ "stwo_core", "stwo_prover_api", "stwo_prover_engine", "stwo_riscv_cpu_integration", "stwo_riscv_frontend", "stwo_cuda_backend", "stwo_circuit_cpu_integration", "stwo_circuit_frontend" }) |name| truth_parity_root.addImport(name, combined_root.import_table.get(name) orelse @panic("missing truth parity dependency"));
    const truth_parity = b.addExecutable(.{ .name = "rv64-m8-truth-parity", .root_module = truth_parity_root });
    truth_parity.linkLibC();
    b.step("build-rv64-m8-truth-parity", "Build the M8 GPU-native TruthJob real-block parity harness (legacy truths recorded, TruthJob proves post hoc)").dependOn(&b.addInstallArtifact(truth_parity, .{}).step);
    // gn-shape (native): GPU-native install-time class builder real-block parity harness.
    const class_build_root = b.createModule(.{ .root_source_file = b.path("rv64_m8_class_build_parity_main.zig"), .target = target, .optimize = optimize });
    for ([_][]const u8{ "stwo_core", "stwo_prover_api", "stwo_prover_engine", "stwo_riscv_cpu_integration", "stwo_riscv_frontend", "stwo_cuda_backend", "stwo_circuit_cpu_integration", "stwo_circuit_frontend" }) |name| class_build_root.addImport(name, combined_root.import_table.get(name) orelse @panic("missing class build parity dependency"));
    const class_build = b.addExecutable(.{ .name = "rv64-m8-class-build-parity", .root_module = class_build_root });
    class_build.linkLibC();
    b.step("build-rv64-m8-class-build-parity", "Build the M8 GPU-native install-time class builder real-block parity harness (legacy classes recorded, install-built classes compared field by field, device warm)").dependOn(&b.addInstallArtifact(class_build, .{}).step);
    // gn-s2 (native): Stage-2 tail (seal, oods_constraint, encoder) real-block parity harness.
    const gn_s2_parity_root = b.createModule(.{ .root_source_file = b.path("rv64_m8_gn_s2_parity_main.zig"), .target = target, .optimize = optimize });
    for ([_][]const u8{ "stwo_core", "stwo_prover_api", "stwo_prover_engine", "stwo_riscv_cpu_integration", "stwo_riscv_frontend", "stwo_cuda_backend", "stwo_circuit_cpu_integration", "stwo_circuit_frontend" }) |name| gn_s2_parity_root.addImport(name, combined_root.import_table.get(name) orelse @panic("missing gn-s2 parity dependency"));
    const gn_s2_parity = b.addExecutable(.{ .name = "rv64-m8-gn-s2-parity", .root_module = gn_s2_parity_root });
    gn_s2_parity.linkLibC();
    b.step("build-rv64-m8-gn-s2-parity", "Build the M8 GPU-native Stage-2 tail real-block parity harness (legacy recorded; seal, oods_constraint, encoder post hoc)").dependOn(&b.addInstallArtifact(gn_s2_parity, .{}).step);
    const gn_s2_check = b.addExecutable(.{ .name = "rv64-m8-gn-s2-parity-check", .root_module = gn_s2_parity_root });
    gn_s2_check.linkLibC();
    b.step("check-rv64-m8-gn-s2-parity", "Type-check the gn-s2 parity harness without emitting a binary").dependOn(&gn_s2_check.step);
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

fn jobTestStep(b: *std.Build, tests: *std.Build.Step.Compile, check_only: bool) *std.Build.Step {
    if (check_only) return &tests.step;
    const run = b.addRunArtifact(tests);
    run.setCwd(b.path("."));
    return &run.step;
}
