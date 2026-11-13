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
    inline for (@import("riscv_cpu_provider_suites.zig").suites) |suite| {
        context.b.step("test-riscv64-" ++ suite[0], "Test RV64 independent provider architecture").dependOn(test_filter.addSuites(context.b, &.{.{
            .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), suite[1], &.{}),
            .minimum = suite[2],
        }}));
    }
    // Preserve the original command and floor across the invariant-owner split.
    context.b.step("test-riscv64-services-gkr-local", "Test neutral GKR kernels and product execution policy").dependOn(test_filter.addCombinedSuites(context.b, &.{
        .{ .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/integrations/riscv_cpu/rv64_services_gkr_local_test_root.zig", &.{}) },
        .{ .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/products/ethereum/statement/cpu/rv64_services_gkr_policy_test_root.zig", &.{}) },
    }, 38));
    context.b.step("test-riscv64-proof", "Prove and verify authenticated RV64 execution").dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/integrations/riscv_cpu/rv64_proof_test_root.zig", &.{}),
        .minimum = 9,
    }}));
    context.b.step("test-riscv64-air", "Test RV64 constraint authority").dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/frontends/riscv/rv64/focused_product_rv64_air_test_root.zig", &.{}),
        .minimum = 35,
    }}));
    const rv64_execution = context.b.step("test-riscv64-execution", "Test experimental RV64IM execution without proof admission");
    rv64_execution.dependOn(test_filter.addCombinedSuites(context.b, &.{
        .{ .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/frontends/riscv/rv64/focused_product_rv64_execution_test_root.zig", &.{}) },
        .{ .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/frontends/riscv/focused_product_rv64_execution_test_root.zig", &.{}) },
        .{ .tests = riscv_cpu_tests.addFocusedTestRoot(testContext(context), "src/frontends/riscv/isa/focused_product_rv64_execution_test_root.zig", &.{}) },
    }, 67));
    // Compile standalone tools without injected proof modules: execution must
    // stay usable independently of the frontend AIR/prover dependency graph.
    for ([_][]const u8{ "diagnostic", "csp_benchmark", "benchmark", "ethereum_execution" }) |tool| {
        const executable = context.b.addExecutable(.{
            .name = context.b.fmt("rv64-{s}-compile-check", .{tool}),
            .root_module = graph.create(context.b, .{
                .product = product,
                .root_source_file = if (std.mem.eql(u8, tool, "ethereum_execution")) "src/products/ethereum/statement/frontend/rv64/ethereum_execution.zig" else context.b.fmt("src/frontends/riscv/rv64/{s}.zig", .{tool}),
                .target = context.target,
                .optimize = context.optimize,
            }),
        });
        rv64_execution.dependOn(&executable.step);
    }
    const tools = [_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "rv64-om-classic-control", .source = "src/products/ethereum/statement/cpu/rv64_om_classic_control_main.zig" },
        .{ .name = "rv64-word16-ethereum", .source = "src/products/ethereum/statement/cpu/rv64_word16_ethereum_main.zig" },
        .{ .name = "rv64-word16-ethereum-gkr", .source = "src/products/ethereum/statement/cpu/rv64_word16_ethereum_gkr_main.zig" },
        .{ .name = "rv64-capture-bench", .source = "src/products/ethereum/statement/cpu/rv64_capture_bench_main.zig" },
        .{ .name = "rv64-logup-gkr-prototype", .source = "src/products/ethereum/statement/cpu/rv64_logup_gkr_prototype_main.zig" },
        .{ .name = "rv64-logup-kernel-bench", .source = "src/integrations/riscv_cpu/rv64_logup_kernel_bench_main.zig" },
        .{ .name = "rv64-word16-combined-services-fixture", .source = "src/products/ethereum/statement/cpu/rv64_word16_combined_services_fixture_main.zig" },
        .{ .name = "rv64-om-sail-qualification", .source = "src/integrations/riscv_cpu/rv64_om_sail_qualification_main.zig" },
        .{ .name = "rv64-word16-sail", .source = "src/integrations/riscv_cpu/rv64_word16_sail_main.zig" },
        .{ .name = "rv64-word16-setup-ownership", .source = "src/products/ethereum/statement/cpu/rv64_word16_setup_ownership_main.zig" },
        .{ .name = "rv64-composition-ir-stats", .source = "src/integrations/riscv_cpu/rv64_composition_ir_stats_main.zig" },
        .{ .name = "rv64-word16-csp", .source = "src/integrations/riscv_cpu/rv64_word16_csp_main.zig" },
        .{ .name = "rv64-word16-global-secp-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_global_secp_fixture_main.zig" },
        .{ .name = "rv64-word16-shared-keccak-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shared_keccak_fixture_main.zig" },
        .{ .name = "rv64-word16-global-keccak-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_global_keccak_fixture_main.zig" },
        .{ .name = "rv64-word16-global-execution", .source = "src/products/ethereum/statement/cpu/rv64_word16_global_execution_main.zig" },
        .{ .name = "rv64-word16-execution-benchmark", .source = "src/products/ethereum/statement/cpu/rv64_word16_execution_benchmark_main.zig" },
        .{ .name = "rv64-load-store-fixture", .source = "src/integrations/riscv_cpu/rv64_load_store_fixture_main.zig" },
        .{ .name = "rv64-closed-ram-fixture", .source = "src/integrations/riscv_cpu/rv64_closed_ram_fixture_main.zig" },
        .{ .name = "rv64-word16-shift-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shift_fixture_main.zig" },
        .{ .name = "rv64-word16-shift-word-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shift_word_fixture_main.zig" },
        .{ .name = "rv64-word16-shift-packed-fixture", .source = "src/integrations/riscv_cpu/rv64_word16_shift_packed_fixture_main.zig" },
        .{ .name = "rv64-function-census", .source = "src/products/ethereum/statement/cpu/rv64_function_census_main.zig" },
        .{ .name = "rv64-word16-weighted-alu", .source = "src/integrations/riscv_cpu/rv64_word16_weighted_alu_main.zig" },
        .{ .name = "rv64-word16-weighted-binary", .source = "src/integrations/riscv_cpu/rv64_word16_weighted_binary_main.zig" },
        .{ .name = "rv64-word16-loop", .source = "src/integrations/riscv_cpu/rv64_word16_loop_main.zig" },
        .{ .name = "rv64-om-retention-plan", .source = "src/integrations/riscv_cpu/rv64_om_retention_plan_main.zig" },
        .{ .name = "rv64-native-gkr-census", .source = "src/integrations/riscv_cpu/rv64_native_gkr_census_main.zig" },
        .{ .name = "rv64-native-gkr-tool", .source = "src/integrations/riscv_cpu/rv64_native_gkr_tool_main.zig" },
        .{ .name = "rv64-secp-fixture", .source = "src/integrations/riscv_cpu/delegations/secp256k1/fixture_main.zig" },
        .{ .name = "rv64-keccak-pair2n-fixture", .source = "src/integrations/riscv_cpu/delegations/keccak/pair2n_main.zig" },
        .{ .name = "rv64-keccak-fixture", .source = "src/integrations/riscv_cpu/delegations/keccak/fixture_main.zig" },
        .{ .name = "rv64-keccak-source-profile", .source = "src/integrations/riscv_cpu/delegations/keccak/source_profile_main.zig" },
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
        .{ .name = "rv64-multiplication-degree3-fixture", .source = "src/integrations/riscv_cpu/delegations/multiplication/degree3_main.zig" },
        .{ .name = "rv64-division-degree3-fixture", .source = "src/integrations/riscv_cpu/delegations/division/degree3_main.zig" },
        .{ .name = "rv64-division-verify", .source = "src/integrations/riscv_cpu/delegations/division/verify_main.zig" },
        .{ .name = "rv64-ethereum-reprove", .source = "src/products/ethereum/statement/cpu/rv64_ethereum_reprove_main.zig" },
        .{ .name = "rv64-ethereum-proof", .source = "src/products/ethereum/statement/cpu/rv64_ethereum_proof_main.zig" },
        .{ .name = "rv64-ram-cost", .source = "src/integrations/riscv_cpu/rv64_ram_cost_main.zig" },
        .{ .name = "rv64-ram-receipt", .source = "src/integrations/riscv_cpu/rv64_ram_receipt_main.zig" },
        .{ .name = "rv64-full-verify", .source = "src/integrations/riscv_cpu/rv64_full_verify_main.zig" },
        .{ .name = "rv64-quotient-benchmark", .source = "src/frontends/riscv/rv64/adapters/rv64_quotient_benchmark_main.zig" },
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
    executables.addObserverProducts(context);
    riscv_poseidon2_pair.add(context, product);
    const host_step = context.b.step(
        "stwo-zig-riscv-cpu",
        "Build the focused Sail RV32IM CPU/SIMD proof CLI",
    );
    host_step.dependOn(&install_host.step);

    executables.addRecursiveDiagnostics(context);

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
    riscv_cpu_tests.addObservationContracts(test_context);

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
                "src/products/riscv/cpu/tests/main_trace_planned_proof_test.zig",
                &.{
                    "one proof-scoped pool preserves exact N=1/2/4 proof identity",
                    "proof-scoped pool failure unwinds before a subsequent proof",
                    "five-region phase meter covers one real independently verified proof",
                    "profiled prepared Tree2 publishes exact interaction work",
                },
            ),
            .minimum = 4,
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
        "src/products/riscv/cpu/tests/recursion_poseidon_leaf_test.zig",
        &.{"recursion Poseidon2 native leaf"},
    )));
    context.b.step(
        "test-riscv-statement-wire",
        "Check shared statement metadata and guest artifact compatibility",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(test_context, "src/frontends/riscv/focused_statement_wire_test_root.zig", &.{ "guest proof artifact", "public input byte binding" }),
        .minimum = 6,
    }}));

    context.b.step(
        "test-riscv-blake3-memory-path",
        "Prove a full-depth BLAKE3 byte-memory opening",
    ).dependOn(test_filter.addSuites(context.b, &.{.{
        .tests = riscv_cpu_tests.addFocusedTestRoot(
            test_context,
            "src/integrations/riscv_cpu/blake3_memory_path_proof_test_root.zig",
            &.{"BLAKE3 memory path proves"},
        ),
        .minimum = 2,
    }}));

    context.b.step(
        "test-riscv-recursion-ingress",
        "Validate production-derived recursive public ingress without proving",
    ).dependOn(test_filter.addRun(context.b, riscv_cpu_tests.addFocusedTestRoot(
        test_context,
        "src/products/riscv/cpu/tests/recursion_ingress_real_guest_test.zig",
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
        "scripts/riscv/riscv_opcode_coverage.py",
        "check",
    });
    test_step.dependOn(&refinement_contract.step);

    const csp_benchmark = context.b.addSystemCommand(&.{
        "python3",
        "scripts/riscv/riscv_csp_benchmark.py",
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
        "scripts/riscv/check_riscv_cpu_product.py",
    });
    test_step.dependOn(&marker_check.step);
}
