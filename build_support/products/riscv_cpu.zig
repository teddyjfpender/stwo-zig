//! Build ownership for the focused Sail RV32IM + CPU/SIMD product.
const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const product_policy = @import("../graph/product.zig");
const riscv_cpu_policy = @import("riscv_cpu_policy.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");
const riscv_cpu_tests = @import("riscv_cpu_tests.zig");
const riscv_refinement = @import("riscv_refinement.zig");
const riscv_poseidon2_pair = @import("riscv_poseidon2_pair.zig");
const sail_oracle_tests = @import("riscv_sail_oracle_tests.zig");
const test_filter = @import("riscv_test_filter.zig");
const product = graph.Product{
    .name = "stwo-riscv-cpu",
    .frontend = .riscv,
    .backend = .cpu,
    .role = .cli,
    .protocol_features = "rv32im-zkvm-v1+sail-authoritative+lifted-pcs-v1",
};
const source_closure = riscv_cpu_policy.source_closure;
pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};
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
    descriptor.validate() catch |err| std.debug.panic(
        "invalid RISC-V CPU descriptor: {s}",
        .{@errorName(err)},
    );
    const host = addExecutable(
        context,
        context.protocol,
        context.target,
        context.optimize,
        "stwo-zig-riscv-cpu",
    );
    const install_host = context.b.addInstallArtifact(host, .{});
    const host_trace = addTraceExecutable(context, context.target, context.optimize, "riscv-trace-dump");
    const install_host_trace = context.b.addInstallArtifact(host_trace, .{});
    const trace_step = context.b.step("riscv-trace-dump", "Build RISC-V trace dumper CLI");
    trace_step.dependOn(&install_host_trace.step);
    riscv_poseidon2_pair.add(context, product);
    const host_step = context.b.step(
        "stwo-zig-riscv-cpu",
        "Build the focused Sail RV32IM CPU/SIMD proof CLI",
    );
    host_step.dependOn(&install_host.step);

    const recursive_csp_producer = addRecursiveCspProducer(context);
    const install_recursive_csp_producer = context.b.addInstallArtifact(
        recursive_csp_producer,
        .{},
    );
    context.b.step(
        "riscv-recursion-csp-producer",
        "Build the canonical one-workload recursive CSP producer",
    ).dependOn(&install_recursive_csp_producer.step);

    const recursion_shape_inspector = addRecursionShapeInspector(context);
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
    const static = addExecutable(
        context,
        graph.createPrivateProtocolModules(context.b, static_target, .ReleaseFast),
        static_target,
        .ReleaseFast,
        "stwo-zig-riscv-cpu-x86_64-linux-musl",
    );
    static.linkage = .static;
    const install_static = context.b.addInstallArtifact(static, .{});
    // Keep both dumpers installed while host tooling resolves the native name.
    const static_trace = addTraceExecutable(context, static_target, .ReleaseFast, "riscv-trace-dump-x86_64-linux-musl");
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
fn addTraceExecutable(
    context: Context,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
) *std.Build.Step.Compile {
    const b = context.b;
    const protocol = if (target.result.cpu.arch == context.target.result.cpu.arch and
        target.result.os.tag == context.target.result.os.tag and
        target.result.abi == context.target.result.abi)
        context.protocol
    else
        graph.createPrivateProtocolModules(b, target, optimize);
    const root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/riscv_trace_cli.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(root);
    integration_graph.addRiscVCpuStack(
        b,
        protocol,
        product,
        target,
        optimize,
        root,
    );
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    return b.addExecutable(.{ .name = name, .root_module = root });
}
fn addExecutable(
    context: Context,
    protocol: graph.ProtocolModules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
) *std.Build.Step.Compile {
    const b = context.b;
    const stwo = createStwoModule(b, protocol, target, optimize);
    const capabilities = riscv_cpu_modules.capabilities(context.b, product, target, optimize);
    const shell = riscv_cpu_modules.binding(context.b, product, target, optimize);
    const adapter = shell.adapterModule(.{
        .protocol = protocol,
        .identity = context.identity,
        .stwo = stwo,
        .capabilities = capabilities,
    });
    const root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/products/riscv_cpu/main.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_riscv_cpu", stwo);
    root.addImport("riscv_adapter", adapter);
    root.addImport("riscv_cpu_capabilities", capabilities);
    shell.addShellImports(root);
    root.addImport(
        "output_transaction",
        riscv_cpu_modules.outputTransaction(context.b, product, target, optimize),
    );
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(b, context.identity, product, target, optimize),
    );
    return b.addExecutable(.{ .name = name, .root_module = root });
}

fn addRecursiveCspProducer(context: Context) *std.Build.Step.Compile {
    const b = context.b;
    const stwo = createStwoModule(
        b,
        context.protocol,
        context.target,
        context.optimize,
    );
    const root = graph.create(b, .{
        .product = riscv_cpu_modules.roleProduct(product, .benchmark),
        .root_source_file = "src/tools/riscv/recursive_csp_producer/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport(
        "recursive_csp_profile_registry",
        recursionProfileRegistryModule(context, .benchmark),
    );
    root.addImport(
        "output_transaction",
        riscv_cpu_modules.outputTransaction(
            context.b,
            product,
            context.target,
            context.optimize,
        ),
    );
    root.addOptions(
        "build_identity",
        graph_identity.buildOptions(b, context.identity),
    );
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            b,
            context.identity,
            riscv_cpu_modules.roleProduct(product, .benchmark),
            context.target,
            context.optimize,
        ),
    );
    return b.addExecutable(.{
        .name = "stwo-zig-riscv-recursive-csp-producer",
        .root_module = root,
    });
}

fn addRecursionShapeInspector(context: Context) *std.Build.Step.Compile {
    const b = context.b;
    const root = graph.create(b, .{
        .product = riscv_cpu_modules.roleProduct(product, .gate),
        .root_source_file = "src/tools/riscv/recursive_csp_shape_inspector/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    _ = graph.addRiscVFrontendImport(
        b,
        context.protocol,
        riscv_cpu_modules.roleProduct(product, .gate),
        context.target,
        context.optimize,
        root,
    );
    root.addImport(
        "atomic_file",
        graph.create(b, .{
            .product = riscv_cpu_modules.roleProduct(product, .gate),
            .root_source_file = "src/interop/atomic_file.zig",
            .target = context.target,
            .optimize = context.optimize,
        }),
    );
    root.addImport(
        "recursive_csp_profile_registry",
        recursionProfileRegistryModule(context, .gate),
    );
    root.addOptions(
        "build_identity",
        graph_identity.buildOptions(b, context.identity),
    );
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            b,
            context.identity,
            riscv_cpu_modules.roleProduct(product, .gate),
            context.target,
            context.optimize,
        ),
    );
    return b.addExecutable(.{
        .name = "stwo-zig-riscv-recursion-shape-inspector",
        .root_module = root,
    });
}

fn recursionProfileRegistryModule(
    context: Context,
    role: graph.Role,
) *std.Build.Module {
    return graph.create(context.b, .{
        .product = riscv_cpu_modules.roleProduct(product, role),
        .root_source_file = "src/tools/riscv/recursive_csp_producer/profile_registry.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
}
fn createStwoModule(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = graph.create(b, .{
        .product = riscv_cpu_modules.roleProduct(product, .library),
        .root_source_file = "src/stwo_riscv_cpu.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(module);
    _ = graph.addProofWireImport(
        b,
        protocol,
        riscv_cpu_modules.roleProduct(product, .library),
        target,
        optimize,
        module,
    );
    integration_graph.addRiscVCpuStack(
        b,
        protocol,
        riscv_cpu_modules.roleProduct(product, .library),
        target,
        optimize,
        module,
    );
    return module;
}
