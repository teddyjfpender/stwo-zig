//! Build ownership for the focused Sail RV32IM + CPU/SIMD product.
const std = @import("std");
const closure_gate = @import("../gates/product_closure.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");
const riscv_cpu_policy = @import("riscv_cpu_policy.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");
const riscv_cpu_tests = @import("riscv_cpu_tests.zig");
const riscv_refinement = @import("riscv_refinement.zig");
const riscv_poseidon2_pair = @import("riscv_poseidon2_pair.zig");
const sail_oracle_tests = @import("riscv_sail_oracle_tests.zig");
const test_filter = @import("riscv_test_filter.zig");
pub const executables = @import("riscv_cpu_executables.zig");
const product = executables.product;
const source_closure = riscv_cpu_policy.source_closure;
pub const Context = executables.Context;
fn testContext(context: Context) riscv_cpu_tests.Context {
    return .{
        .b = context.b,
        .target = context.target,
        .optimize = context.optimize,
        .identity = context.identity,
        .protocol = context.protocol,
        .product = product,
    };
}
pub const descriptor = product_policy.Descriptor{
    .product = product,
    .state = .released,
    .target_support = .any,
    .build_step = "stwo-zig-riscv-cpu",
    .test_step = "test-riscv-cpu-product",
    .executable = "stwo-zig-riscv-cpu",
    .installed_artifacts = &.{"stwo-zig-riscv-cpu"},
    .release_gates = &.{"riscv-release-gate"},
    .dependencies = .{ .module_roots = source_closure.entry_roots },
    .source_closure = source_closure,
};
pub fn addProduct(context: Context) void {
    inline for (.{
        .{ "program", "src/frontends/riscv/rv64_program_test_root.zig", 9 },
        .{ "simd-fields", "src/frontends/riscv/rv64_simd_fields_test_root.zig", 6 },
        .{ "parallel", "src/frontends/riscv/rv64_parallel_test_root.zig", 8 },
        .{ "coset", "src/frontends/riscv/rv64_coset_evaluation_test_root.zig", 6 },
        .{ "full-capture", "src/integrations/riscv_cpu/rv64_full_capture_test_root.zig", 9 },
        .{ "full-proof", "src/integrations/riscv_cpu/rv64_full_proof_test_root.zig", 3 },
        .{ "multiplication", "src/integrations/riscv_cpu/delegations/multiplication/test_root.zig", 6 },
        .{ "keccak-cpu", "src/integrations/riscv_cpu/delegations/keccak/cpu_test_root.zig", 11 },
        .{ "ethereum-chain", "src/integrations/riscv_cpu/rv64_ethereum_chain_test_root.zig", 12 },
        .{ "distributed-functional", "src/integrations/riscv_cpu/rv64_distributed_manifest_test_root.zig", 16 },
        .{ "word16-global-memory", "src/integrations/riscv_cpu/rv64_word16_global_memory_test_root.zig", 4 },
        .{ "word16-execution-prepared", "src/integrations/riscv_cpu/rv64_word16_execution_prepared_test_root.zig", 10 },
        .{ "word16-keccak-bridge", "src/integrations/riscv_cpu/rv64_word16_keccak_bridge_test_root.zig", 9 },
        .{ "word16-global-execution", "src/integrations/riscv_cpu/rv64_word16_global_execution_test_root.zig", 15 },
        .{ "word16-memory", "src/integrations/riscv_cpu/rv64_word16_memory_test_root.zig", 14 },
        .{ "word16-chips", "src/frontends/riscv/rv64_word16_chips_test_root.zig", 8 },
        .{ "word16-binary-proof", "src/integrations/riscv_cpu/rv64_word16_binary_proof_test_root.zig", 2 },
        .{ "ethereum-packet-control", "src/integrations/riscv_cpu/rv64_ethereum_packet_control_test_root.zig", 2 },
        .{ "closed-load-store", "src/integrations/riscv_cpu/rv64_load_store_test_root.zig", 15 },
        .{ "closed-ram", "src/integrations/riscv_cpu/rv64_closed_ram_test_root.zig", 11 },
        .{ "word16-shift", "src/frontends/riscv/rv64_word16_shift_test_root.zig", 8 },
        .{ "word16-shift-proof", "src/integrations/riscv_cpu/rv64_word16_shift_proof_test_root.zig", 2 },
        .{ "word16-shift-word", "src/frontends/riscv/rv64_word16_shift_word_test_root.zig", 9 },
        .{ "word16-shift-word-proof", "src/integrations/riscv_cpu/rv64_word16_shift_word_proof_test_root.zig", 2 },
        .{ "word16-shift-packed-table", "src/frontends/riscv/rv64_word16_shift_packed_table_test_root.zig", 6 },
        .{ "word16-shift-source", "src/frontends/riscv/rv64_word16_shift_source_test_root.zig", 7 },
        .{ "word16-shift-packed-proof", "src/integrations/riscv_cpu/rv64_word16_shift_word_packed_proof_test_root.zig", 2 },
        .{ "word16-index-authority", "src/frontends/riscv/rv64_index_control_test_root.zig", 7 },
        .{ "word16-parallel-interaction", "src/integrations/riscv_cpu/rv64_word16_parallel_interaction_test_root.zig", 4 },
        .{ "word16-index-control", "src/integrations/riscv_cpu/rv64_word16_index_control_test_root.zig", 9 },
        .{ "word16-alu-parallel-interaction", "src/frontends/riscv/rv64_alu_parallel_interaction_test_root.zig", 4 },
        .{ "word16-rom-lookup", "src/frontends/riscv/rv64_rom_lookup_test_root.zig", 4 },
        .{ "word16-native-projection", "src/integrations/riscv_cpu/rv64_word16_native_projection_test_root.zig", 3 },
        .{ "work-packet", "src/integrations/riscv_cpu/rv64_work_packet_test_root.zig", 8 },
        .{ "word16-cpu", "src/integrations/riscv_cpu/rv64_word16_cpu_test_root.zig", 3 },
        .{ "word16-weighted-binary", "src/integrations/riscv_cpu/rv64_word16_weighted_binary_test_root.zig", 4 },
        .{ "word16-binary-source", "src/frontends/riscv/rv64_word16_binary_source_test_root.zig", 10 },
        .{ "word16-weighted-alu", "src/integrations/riscv_cpu/rv64_word16_weighted_alu_test_root.zig", 4 },
        .{ "word16-execution", "src/integrations/riscv_cpu/rv64_word16_execution_test_root.zig", 16 },
        .{ "word16-execution-source", "src/integrations/riscv_cpu/rv64_word16_execution_source_test_root.zig", 6 },
        .{ "word16-execution-coordinator", "src/integrations/riscv_cpu/rv64_word16_execution_coordinator_test_root.zig", 20 },
        .{ "word16-alu", "src/frontends/riscv/rv64_word16_alu_test_root.zig", 21 },
        .{ "word16-alu-proof", "src/integrations/riscv_cpu/rv64_word16_alu_proof_test_root.zig", 2 },
        .{ "word16-thin-cpu", "src/integrations/riscv_cpu/rv64_word16_thin_cpu_test_root.zig", 14 },
        .{ "distributed-execution", "src/integrations/riscv_cpu/rv64_distributed_execution_test_root.zig", 10 },
        .{ "ethereum-chip-plan", "src/integrations/riscv_cpu/rv64_ethereum_chip_plan_test_root.zig", 8 },
        .{ "verifier-cache", "src/integrations/riscv_cpu/rv64_verifier_cache_test_root.zig", 3 },
        .{ "point-evaluation", "src/integrations/riscv_cpu/rv64_point_evaluation_test_root.zig", 3 },
        .{ "cpu-degree-diagnostic", "src/integrations/riscv_cpu/rv64_cpu_degree_diagnostic_test_root.zig", 2 },
        .{ "borrowed-services", "src/integrations/riscv_cpu/delegations/common/borrowed_test_root.zig", 4 },
        .{ "lean-proof", "src/integrations/riscv_cpu/rv64_lean_test_root.zig", 3 },
        .{ "division", "src/integrations/riscv_cpu/delegations/division/test_root.zig", 10 },
        .{ "authenticated-execution", "src/integrations/riscv_cpu/rv64_authenticated_test_root.zig", 1 },
        .{ "ram", "src/integrations/riscv_cpu/rv64_ram_test_root.zig", 1 },
        .{ "program-proof", "src/integrations/riscv_cpu/rv64_program_proof_test_root.zig", 3 },
        .{ "providers", "src/integrations/riscv_cpu/rv64_providers_test_root.zig", 8 },
        .{ "main-arena", "src/integrations/riscv_cpu/rv64_main_arena_test_root.zig", 12 },
        .{ "secp", "src/integrations/riscv_cpu/delegations/secp256k1/test_root.zig", 30 },
        .{ "keccak", "src/integrations/riscv_cpu/delegations/keccak/test_root.zig", 33 },
        .{ "keccak-quartet", "src/integrations/riscv_cpu/delegations/keccak/quartet_test_root.zig", 6 },
        .{ "poseidon-simd", "src/integrations/riscv_cpu/rv64_poseidon_simd_test_root.zig", 4 },
        .{ "pcs-commit", "src/integrations/riscv_cpu/pcs_commit_profile_test_root.zig", 2 },
        .{ "pcs-owned", "src/integrations/riscv_cpu/pcs_owned_profile_test_root.zig", 4 },
        .{ "recursion", "src/integrations/riscv_cpu/rv64_recursion_test_root.zig", 1 },
    }) |suite| {
        context.b.step("test-riscv64-" ++ suite[0], "Test RV64 independent provider architecture").dependOn(test_filter.addSuites(context.b, &.{.{
            .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), suite[1], &.{}),
            .minimum = suite[2],
        }}));
    }
    context.b.step("test-riscv64-proof", "Prove and verify authenticated RV64 execution").dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/integrations/riscv_cpu/rv64_proof_test_root.zig", &.{}),
        .minimum = 9,
    }}));
    context.b.step("test-riscv64-air", "Test RV64 constraint authority").dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/frontends/riscv/rv64_air_test_root.zig", &.{}),
        .minimum = 35,
    }}));
    const rv64_execution = context.b.step("test-riscv64-execution", "Test experimental RV64IM execution without proof admission");
    rv64_execution.dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/frontends/riscv/rv64_execution_test_root.zig", &.{}),
        .minimum = 67,
    }}));
    // Compile standalone tools without injected proof modules: execution must
    // stay usable independently of the frontend AIR/prover dependency graph.
    for ([_][]const u8{ "diagnostic", "csp_benchmark", "benchmark", "ethereum_execution" }) |tool| {
        const executable = context.b.addExecutable(.{
            .name = context.b.fmt("rv64-{s}-compile-check", .{tool}),
            .root_module = graph.create(context.b, .{
                .product = product,
                .root_source_file = context.b.fmt("src/frontends/riscv/rv64/{s}.zig", .{tool}),
                .target = context.target,
                .optimize = context.optimize,
            }),
        });
        rv64_execution.dependOn(&executable.step);
    }
    const tools = [_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "rv64-word16-global-keccak-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_global_keccak_fixture_main.zig" },
        .{ .name = "rv64-word16-global-execution", .source = "src/integrations/riscv_cpu/rv64_word16_global_execution_main.zig" },
        .{ .name = "rv64-word16-execution-benchmark", .source = "src/integrations/riscv_cpu/rv64_word16_execution_benchmark_main.zig" },
        .{ .name = "rv64-load-store-fixture", .source = "src/integrations/riscv_cpu/rv64_load_store_fixture_main.zig" },
        .{ .name = "rv64-closed-ram-fixture", .source = "src/integrations/riscv_cpu/rv64_closed_ram_fixture_main.zig" },
        .{ .name = "rv64-word16-shift-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shift_fixture_main.zig" },
        .{ .name = "rv64-word16-shift-word-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shift_word_fixture_main.zig" },
        .{ .name = "rv64-word16-shift-packed-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shift_packed_fixture_main.zig" },
        .{ .name = "rv64-function-census", .source = "src/integrations/riscv_cpu/rv64_function_census_main.zig" },
        .{ .name = "rv64-word16-weighted-alu", .source = "src/integrations/riscv_cpu/rv64_word16_weighted_alu_main.zig" },
        .{ .name = "rv64-word16-weighted-binary", .source = "src/integrations/riscv_cpu/rv64_word16_weighted_binary_main.zig" },
        .{ .name = "rv64-word16-loop", .source = "src/integrations/riscv_cpu/rv64_word16_loop_main.zig" },
        .{ .name = "rv64-secp-fixture", .source = "src/integrations/riscv_cpu/delegations/secp256k1/fixture_main.zig" },
        .{ .name = "rv64-keccak-fixture", .source = "src/integrations/riscv_cpu/delegations/keccak/fixture_main.zig" },
        .{ .name = "rv64-distributed-execution-fixture", .source = "src/integrations/riscv_cpu/rv64_distributed_execution_fixture_main.zig" },
        .{ .name = "rv64-distributed-functional-fixture", .source = "src/integrations/riscv_cpu/rv64_distributed_functional_fixture_main.zig" },
        .{ .name = "rv64-word16-binary-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_binary_fixture_main.zig" },
        .{ .name = "rv64-word16-alu-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_alu_fixture_main.zig" },
        .{ .name = "rv64-qualification", .source = "src/integrations/riscv_cpu/rv64_qualification_main.zig" },
        .{ .name = "rv64-csp-windows", .source = "src/integrations/riscv_cpu/rv64_csp_windows_main.zig" },
        .{ .name = "rv64-window-verify", .source = "src/integrations/riscv_cpu/rv64_window_verify_main.zig" },
        .{ .name = "rv64-csp-full", .source = "src/integrations/riscv_cpu/rv64_csp_full_main.zig" },
        .{ .name = "rv64-multiplication-verify", .source = "src/integrations/riscv_cpu/delegations/multiplication/verify_main.zig" },
        .{ .name = "rv64-keccak-cpu-verify", .source = "src/integrations/riscv_cpu/delegations/keccak/verify_main.zig" },
        .{ .name = "rv64-lean-verify", .source = "src/integrations/riscv_cpu/rv64_lean_verify_main.zig" },
        .{ .name = "rv64-division-verify", .source = "src/integrations/riscv_cpu/delegations/division/verify_main.zig" },
        .{ .name = "rv64-ethereum-reprove", .source = "src/integrations/riscv_cpu/rv64_ethereum_reprove_main.zig" },
        .{ .name = "rv64-ethereum-proof", .source = "src/integrations/riscv_cpu/rv64_ethereum_proof_main.zig" },
        .{ .name = "rv64-ram-cost", .source = "src/integrations/riscv_cpu/rv64_ram_cost_main.zig" },
        .{ .name = "rv64-ram-receipt", .source = "src/integrations/riscv_cpu/rv64_ram_receipt_main.zig" },
        .{ .name = "rv64-full-verify", .source = "src/integrations/riscv_cpu/rv64_full_verify_main.zig" },
        .{ .name = "rv64-quotient-benchmark", .source = "src/frontends/riscv/rv64_quotient_benchmark_main.zig" },
        .{ .name = "pcs-commit-profile", .source = "src/integrations/riscv_cpu/pcs_commit_profile_main.zig" },
        .{ .name = "pcs-owned-profile", .source = "src/integrations/riscv_cpu/pcs_owned_profile_main.zig" },
    };
    for (tools) |tool| {
        const entry = @import("riscv_delegation_entry.zig").select(tool.source, .cli);
        const tool_root = graph.create(context.b, .{
            .product = product,
            .root_source_file = if (entry) |value| value.root else tool.source,
            .target = context.target,
            .optimize = context.optimize,
        });
        if (entry) |value| @import("riscv_delegation_entry.zig").bind(context.b, tool_root, value);
        context.protocol.addImports(tool_root);
        _ = graph.addProofWireImport(context.b, context.protocol, product, context.target, context.optimize, tool_root);
        @import("../graph/integrations.zig").addRiscVCpuStack(context.b, context.protocol, product, context.target, context.optimize, tool_root);
        const executable = context.b.addExecutable(.{ .name = tool.name, .root_module = tool_root });
        const install = context.b.addInstallArtifact(executable, .{});
        context.b.step(tool.name, "Build proof qualification and performance diagnostics").dependOn(&install.step);
    }
    descriptor.validate() catch |err| std.debug.panic(
        "invalid RISC-V CPU descriptor: {s}",
        .{@errorName(err)},
    );
    const host = executables.addExecutable(
        context,
        context.protocol,
        context.target,
        context.optimize,
        "stwo-zig-riscv-cpu",
    );
    const install_host = context.b.addInstallArtifact(host, .{});
    const host_trace = executables.addTraceExecutable(context, context.target, context.optimize, "riscv-trace-dump");
    const install_host_trace = context.b.addInstallArtifact(host_trace, .{});
    const trace_step = context.b.step("riscv-trace-dump", "Build RISC-V trace dumper CLI");
    trace_step.dependOn(&install_host_trace.step);
    const pc_hotspot = executables.addObserver(context, context.target, context.optimize, .pc_hotspot);
    const install_pc_hotspot = context.b.addInstallArtifact(pc_hotspot, .{});
    context.b.step(
        "riscv-pc-hotspot-observer",
        "Build the bounded RISC-V retirement PC-hotspot observer",
    ).dependOn(&install_pc_hotspot.step);
    const function_value = executables.addObserver(context, context.target, context.optimize, .function_value);
    const install_function_value = context.b.addInstallArtifact(function_value, .{});
    context.b.step(
        "riscv-function-value-observer",
        "Build the bounded RISC-V function-load value observer",
    ).dependOn(&install_function_value.step);
    const analyze_legacy_semantic = executables.addObserver(context, context.target, context.optimize, .legacy_semantics);
    const install_analyze_legacy_semantic = context.b.addInstallArtifact(
        analyze_legacy_semantic,
        .{},
    );
    context.b.step(
        "riscv-analyze-legacy-semantic-observer",
        "Build the bounded Revm-42 analyze_legacy semantic observer",
    ).dependOn(&install_analyze_legacy_semantic.step);
    const memcpy_hotspot = executables.addObserver(context, context.target, context.optimize, .memcpy_hotspot);
    const install_memcpy_hotspot = context.b.addInstallArtifact(memcpy_hotspot, .{});
    context.b.step(
        "riscv-memcpy-hotspot-observer",
        "Build the bounded RISC-V memcpy-call hotspot observer",
    ).dependOn(&install_memcpy_hotspot.step);
    const memcpy_admission = executables.addObserver(context, context.target, context.optimize, .memcpy_admission);
    const install_memcpy_admission = context.b.addInstallArtifact(
        memcpy_admission,
        .{},
    );
    context.b.step(
        "riscv-memcpy-admission-observer",
        "Build the exact RISC-V bulk-memcpy admission observer",
    ).dependOn(&install_memcpy_admission.step);
    riscv_poseidon2_pair.add(context, product);
    const host_step = context.b.step(
        "stwo-zig-riscv-cpu",
        "Build the focused Sail RV32IM CPU/SIMD proof CLI",
    );
    host_step.dependOn(&install_host.step);

    const recursive_csp_producer = executables.addRecursiveCspProducer(context);
    const install_recursive_csp_producer = context.b.addInstallArtifact(
        recursive_csp_producer,
        .{},
    );
    context.b.step(
        "riscv-recursion-csp-producer",
        "Build the canonical one-workload recursive CSP producer",
    ).dependOn(&install_recursive_csp_producer.step);

    const recursion_shape_inspector = executables.addRecursionShapeInspector(context);
    const install_recursion_shape_inspector = context.b.addInstallArtifact(
        recursion_shape_inspector,
        .{},
    );
    context.b.step(
        "riscv-recursion-shape-inspector",
        "Build the proof-independent canonical workload shape inspector",
    ).dependOn(&install_recursion_shape_inspector.step);

    const static_target = context.b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
    });
    const static = executables.addExecutable(
        context,
        graph.createPrivateProtocolModules(context.b, static_target, .ReleaseFast),
        static_target,
        .ReleaseFast,
        "stwo-zig-riscv-cpu-x86_64-linux-musl",
    );
    static.linkage = .static;
    const install_static = context.b.addInstallArtifact(static, .{});
    // Keep both dumpers installed while host tooling resolves the native name.
    const static_trace = executables.addTraceExecutable(context, static_target, .ReleaseFast, "riscv-trace-dump-x86_64-linux-musl");
    static_trace.linkage = .static;
    const install_static_trace = context.b.addInstallArtifact(static_trace, .{});
    // Refuse cross-target names that would overwrite a host install artifact.
    for ([_]*std.Build.Step.Compile{ static, static_trace }) |cross| {
        for ([_]*std.Build.Step.Compile{ host, host_trace }) |native| {
            if (std.mem.eql(u8, cross.name, native.name)) std.debug.panic(
                "RISC-V CPU product installs cross-target {s} over the host binary",
                .{cross.name},
            );
        }
    }
    const static_step = context.b.step(
        "stwo-zig-riscv-cpu-static",
        "Build the static x86_64-linux-musl RISC-V CPU challenge executable",
    );
    static_step.dependOn(&install_static.step);
    static_step.dependOn(&install_static_trace.step);

    const test_context = testContext(context);

    const core_prover_tests = riscv_cpu_tests.addCoreProverTests(test_context);
    const exhaustive_tests = riscv_cpu_tests.addExhaustiveTests(test_context);
    const air_satisfaction_exports = riscv_cpu_tests.addAirSatisfactionExportTests(test_context);
    const run_air_satisfaction_exports = test_filter.addSuites(context.b, &.{.{
        .tests = air_satisfaction_exports,
        .minimum = 2,
    }});
    const test_step = context.b.step(
        "test-riscv-cpu-product",
        "Test the focused RISC-V CPU product shell and capability surface",
    );
    test_step.dependOn(test_filter.addSuites(context.b, riscv_cpu_tests.addTests(test_context)));
    test_step.dependOn(sail_oracle_tests.add(
        context.b,
        riscv_cpu_modules.roleProduct(product, .@"test"),
        context.protocol,
        context.target,
        context.optimize,
    ));
    context.b.step(
        "test-riscv-release-exhaustive",
        "Run the exhaustive RISC-V proof and adversarial release suites",
    ).dependOn(test_filter.addRun(context.b, exhaustive_tests));
    context.b.step(
        "test-riscv-prover-core",
        "Run the RISC-V prover corpus without the separately retained committed-witness mutation suites",
    ).dependOn(test_filter.addRun(context.b, core_prover_tests));
    const proof_pool_parity_tests = riscv_cpu_tests.addTestRoot(test_context, .{
        .exhaustive = true,
        .filters = &.{
            "one proof-scoped pool preserves exact N=1/2/4 proof identity",
            "proof-scoped pool failure unwinds before a subsequent proof",
        },
    });
    const proof_pool_parity_run = test_filter.addSuites(context.b, &.{.{
        .tests = proof_pool_parity_tests,
        // A stale pinned filter previously reduced this target to the unnamed
        // aggregation shell, which exits successfully without running either
        // proof.  Pin both named tests at the build boundary.
        .minimum = 2,
    }});
    context.b.step(
        "test-riscv-planned-tree1",
        "Run exact predecessor versus N=1/2/4 full-proof pool parity",
    ).dependOn(proof_pool_parity_run);
    context.b.step(
        "test-riscv-proof-pool-parity",
        "Run exact Tree-1/Tree-2/quotient/opening pool parity and recovery",
    ).dependOn(proof_pool_parity_run);
    const profile_partition_run = test_filter.addSuites(context.b, &.{
        .{
            .tests = riscv_cpu_tests.addProfilePartitionTests(test_context),
            .minimum = riscv_cpu_tests.profile_partition_test_names.len,
        },
        .{
            .tests = riscv_cpu_tests.addFocusedTestRoot(
                test_context,
                "src/tests/riscv/main_trace_planned_proof_test.zig",
                &.{
                    "one proof-scoped pool preserves exact N=1/2/4 proof identity",
                    "five-region phase meter covers one real independently verified proof",
                    "profiled prepared Tree2 publishes exact interaction work",
                },
            ),
            .minimum = 3,
        },
    });
    context.b.step(
        "test-riscv-profile-partition",
        "Run exact witness/proving partition and profiled Tree-2 custody gates",
    ).dependOn(profile_partition_run);
    context.b.step(
        "test-riscv-recursion-poseidon-leaf",
        "Prove and verify one RISC-V leaf under the recursion Poseidon2 protocol",
    ).dependOn(test_filter.addRun(context.b, riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/tests/riscv/recursion_poseidon_leaf_test.zig",
        &.{"recursion Poseidon2 native leaf"},
    )));
    context.b.step(
        "test-riscv-statement-wire",
        "Check shared statement metadata and guest artifact compatibility",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(test_context, "src/frontends/riscv/guest_precompile_test_root.zig", &.{ "guest proof artifact", "public input byte binding" }),
        .minimum = 6,
    }}));

    context.b.step(
        "test-riscv-blake3-memory-path",
        "Prove a full-depth BLAKE3 byte-memory opening",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(
            test_context,
            "src/frontends/riscv/blake3_memory_path_proof_test_root.zig",
            &.{"BLAKE3 memory path proves"},
        ),
        .minimum = 2,
    }}));
    context.b.step(
        "test-riscv-blake3-identities",
        "Prove paired BLAKE3 Span identities with trusted preprocessing",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(
            test_context,
            "src/frontends/riscv/blake3_span_identity_proof_test_root.zig",
            &.{"BLAKE3 paired Span identities"},
        ),
        .minimum = 1,
    }}));

    context.b.step(
        "test-riscv-recursion-ingress",
        "Validate production-derived recursive public ingress without proving",
    ).dependOn(test_filter.addRun(context.b, riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/tests/riscv/recursion_ingress_real_guest_test.zig",
        &.{"recursive public ingress accepts production-derived self-loop guest"},
    )));
    context.b.step(
        "test-riscv-recursion-typed-control",
        "Prove and independently verify the typed universal-control adapter",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addTestRoot(test_context, .{
            .exhaustive = true,
            .filters = &.{"typed recursion control native PCS FRI adapter"},
        }),
        .minimum = 1,
    }}));
    context.b.step(
        "test-riscv-rigidity",
        "Run the full witness-rigidity sweep over every committed opcode column",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addRigidityTests(test_context),
        .minimum = 1,
    }}));
    const air_satisfaction_export_step = context.b.step(
        "test-riscv-air-satisfaction-export",
        "Export committed traces for the independent AIR satisfaction checker",
    );
    air_satisfaction_export_step.dependOn(run_air_satisfaction_exports);
    const air_satisfaction_check = context.b.addSystemCommand(&.{
        "python3",
        "-m",
        "unittest",
        "scripts.tests.test_air_satisfaction",
        "scripts.tests.test_air_satisfaction_infrastructure",
    });
    air_satisfaction_check.step.dependOn(run_air_satisfaction_exports);
    context.b.step(
        "test-riscv-air-satisfaction",
        "Export and independently check all RISC-V AIR main-trace components",
    ).dependOn(&air_satisfaction_check.step);
    riscv_refinement.addPilot(context.b, context.target, context.optimize, context.protocol);
    const refinement_contract = context.b.addSystemCommand(&.{
        "python3",
        "scripts/riscv_opcode_coverage.py",
        "check",
    });
    test_step.dependOn(&refinement_contract.step);

    const csp_benchmark = context.b.addSystemCommand(&.{
        "python3",
        "scripts/riscv_csp_benchmark.py",
    });
    csp_benchmark.step.dependOn(&install_host.step);
    csp_benchmark.step.dependOn(&install_host_trace.step);
    context.b.step(
        "riscv-csp-bench",
        "Run the pinned EthProofs CSP benchmark matrix",
    ).dependOn(&csp_benchmark.step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = host,
        .static_binary = static,
    });
    test_step.dependOn(&closure_check.step);
    const marker_check = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_riscv_cpu_product.py",
    });
    test_step.dependOn(&marker_check.step);
}
