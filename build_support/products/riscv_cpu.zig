//! Build ownership for the focused Sail RV32IM + CPU/SIMD product.
const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const product_policy = @import("../graph/product.zig");
const riscv_refinement = @import("riscv_refinement.zig");
const test_filter = @import("riscv_test_filter.zig");
const product = graph.Product{
    .name = "stwo-riscv-cpu",
    .frontend = .riscv,
    .backend = .cpu,
    .role = .cli,
    .protocol_features = "rv32im-zkvm-v1+sail-authoritative+lifted-pcs-v1",
};
const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{
        "src/products/riscv_cpu/main.zig",
        "src/stwo_riscv_cpu.zig",
        "src/riscv_trace_cli.zig",
        "src/frontends/riscv/refinement_ir_export_test.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo", .source = "src/stwo_riscv_cpu.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_proof_wire", .source = "src/interop/proof_wire/mod.zig" },
        .{ .name = "stwo_riscv_frontend", .source = "src/frontends/riscv/mod.zig" },
        .{ .name = "stwo_riscv_cpu", .source = "src/stwo_riscv_cpu.zig" },
        .{ .name = "stwo_prover_api", .source = "src/prover_api/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
        .{ .name = "stwo_riscv_cpu_integration", .source = "src/integrations/riscv_cpu/mod.zig" },
        .{ .name = "riscv_adapter", .source = "src/integrations/riscv_cpu/proof_adapter.zig" },
        .{ .name = "riscv_cpu_capabilities", .source = "src/products/riscv_cpu/capabilities.zig" },
        .{ .name = "riscv_shared_app", .source = "src/products/riscv_shared/app.zig" },
        .{ .name = "riscv_shared_registry", .source = "src/products/riscv_shared/registry.zig" },
        .{ .name = "riscv_shared_cli", .source = "src/products/riscv_shared/cli.zig" },
        .{ .name = "output_transaction", .source = "src/interop/output_transaction.zig" },
    },
    .generated_imports = &.{"aggregate_capabilities"},
    .allowed_files = &.{
        "src/products/riscv_cpu/main.zig",
        "src/stwo_riscv_cpu.zig",
        "src/riscv_trace_cli.zig",
        "src/interop/atomic_file.zig",
        "src/interop/output_transaction.zig",
        "src/interop/postcard.zig",
        "src/interop/proof_wire/mod.zig",
        "src/interop/riscv_artifact.zig",
        "src/products/riscv_cpu/capabilities.zig",
    },
    .allowed_prefixes = &.{
        "src/core",
        "src/backend",
        "src/backends/cpu_scalar",
        "src/prover",
        "src/prover_api",
        "src/frontends/riscv",
        "src/integrations/riscv_cpu",
        "src/products/riscv_cpu",
        "src/products/riscv_shared",
        "src/interop/postcard",
        "src/interop/riscv_artifact",
        "src/tools/riscv/trace",
    },
    .forbidden_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
        "cuda",
    },
};
pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};
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
    const host_trace = addTraceExecutable(context, context.target, context.optimize);
    const install_host_trace = context.b.addInstallArtifact(host_trace, .{});
    const trace_step = context.b.step("riscv-trace-dump", "Build RISC-V trace dumper CLI");
    trace_step.dependOn(&install_host_trace.step);
    const host_step = context.b.step(
        "stwo-zig-riscv-cpu",
        "Build the focused Sail RV32IM CPU/SIMD proof CLI",
    );
    host_step.dependOn(&install_host.step);

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
    const static_trace = addTraceExecutable(context, static_target, .ReleaseFast);
    static_trace.linkage = .static;
    const install_static_trace = context.b.addInstallArtifact(static_trace, .{});
    const static_step = context.b.step(
        "stwo-zig-riscv-cpu-static",
        "Build the static x86_64-linux-musl RISC-V CPU challenge executable",
    );
    static_step.dependOn(&install_static.step);
    static_step.dependOn(&install_static_trace.step);

    const tests = addTests(context);
    const integration_tests = addIntegrationTests(context);
    const core_prover_tests = addCoreProverTests(context);
    const exhaustive_tests = addExhaustiveTests(context);
    const air_satisfaction_exports = addAirSatisfactionExportTests(context);
    const run_air_satisfaction_exports = test_filter.addRun(context.b, air_satisfaction_exports);
    const test_step = context.b.step(
        "test-riscv-cpu-product",
        "Test the focused RISC-V CPU product shell and capability surface",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);
    test_step.dependOn(test_filter.addRun(context.b, integration_tests));
    context.b.step(
        "test-riscv-release-exhaustive",
        "Run the exhaustive RISC-V proof and adversarial release suites",
    ).dependOn(test_filter.addRun(context.b, exhaustive_tests));
    context.b.step(
        "test-riscv-prover-core",
        "Run the RISC-V prover corpus without the separately retained committed-witness mutation suites",
    ).dependOn(test_filter.addRun(context.b, core_prover_tests));
    context.b.step(
        "test-riscv-rigidity",
        "Run the full witness-rigidity sweep over every committed opcode column",
    ).dependOn(test_filter.addRun(context.b, addRigidityTests(context)));
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
    return b.addExecutable(.{ .name = "riscv-trace-dump", .root_module = root });
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
    const capabilities = createCapabilitiesModule(context, target, optimize);
    const adapter = createAdapterModule(context, protocol, stwo, capabilities, target, optimize);
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
    root.addImport("riscv_shared_app", createSharedModule(
        context,
        "src/products/riscv_shared/app.zig",
        target,
        optimize,
    ));
    root.addImport("riscv_shared_registry", createSharedModule(
        context,
        "src/products/riscv_shared/registry.zig",
        target,
        optimize,
    ));
    root.addImport("riscv_shared_cli", createSharedModule(
        context,
        "src/products/riscv_shared/cli.zig",
        target,
        optimize,
    ));
    root.addImport("output_transaction", createOutputTransaction(context, target, optimize));
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(b, context.identity, product, target, optimize),
    );
    return b.addExecutable(.{ .name = name, .root_module = root });
}
fn addTests(context: Context) *std.Build.Step.Compile {
    const b = context.b;
    const stwo = createStwoModule(b, context.protocol, context.target, context.optimize);
    const capabilities = createCapabilitiesModule(context, context.target, context.optimize);
    const adapter = createAdapterModule(
        context,
        context.protocol,
        stwo,
        capabilities,
        context.target,
        context.optimize,
    );
    const test_product = graph.Product{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = .@"test",
        .protocol_features = product.protocol_features,
    };
    const root = graph.create(b, .{
        .product = test_product,
        .root_source_file = "src/products/riscv_cpu/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        test_product,
        context.target,
        context.optimize,
        root,
    );
    root.addImport("stwo", stwo);
    root.addImport("stwo_riscv_cpu", stwo);
    root.addImport("riscv_adapter", adapter);
    root.addImport("riscv_cpu_capabilities", capabilities);
    root.addImport("riscv_shared_app", createSharedModule(
        context,
        "src/products/riscv_shared/app.zig",
        context.target,
        context.optimize,
    ));
    root.addImport("riscv_shared_registry", createSharedModule(
        context,
        "src/products/riscv_shared/registry.zig",
        context.target,
        context.optimize,
    ));
    root.addImport("riscv_shared_cli", createSharedModule(
        context,
        "src/products/riscv_shared/cli.zig",
        context.target,
        context.optimize,
    ));
    root.addImport(
        "output_transaction",
        createOutputTransaction(context, context.target, context.optimize),
    );
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            b,
            context.identity,
            test_product,
            context.target,
            context.optimize,
        ),
    );
    return b.addTest(.{ .root_module = root });
}
/// Which suites a `src/tests.zig` binary compiles in, and which of its tests it
/// runs. Named rather than positional: four booleans at a call site say nothing
/// about which sweep a step is paying for.
const TestRoot = struct {
    exhaustive: bool = false,
    committed_mutations: bool = false,
    /// Full witness-rigidity sweep instead of the sampled default. The sampled
    /// default keeps every opcode selector and every committed column covered
    /// at a fraction of the probe count; the full sweep re-probes every honest
    /// row the corpus materialises.
    rigidity_exhaustive: bool = false,
    filters: []const []const u8 = &.{},
};
fn addIntegrationTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{});
}

fn addCoreProverTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{ .exhaustive = true });
}
fn addExhaustiveTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{
        .exhaustive = true,
        .committed_mutations = true,
        .rigidity_exhaustive = true,
    });
}

fn addRigidityTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{
        .exhaustive = true,
        .rigidity_exhaustive = true,
        .filters = &.{"witness rigidity"},
    });
}

fn addAirSatisfactionExportTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{
        .exhaustive = true,
        .committed_mutations = true,
        .filters = &.{ "committed trace export", "uniqueness IR: emit every family" },
    });
}

fn addTestRoot(context: Context, options: TestRoot) *std.Build.Step.Compile {
    const b = context.b;
    const test_product = graph.Product{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = .@"test",
        .protocol_features = product.protocol_features,
    };
    const root = graph.create(b, .{
        .product = test_product,
        .root_source_file = "src/tests.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    _ = graph.addProofWireImport(
        b,
        context.protocol,
        test_product,
        context.target,
        context.optimize,
        root,
    );
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        test_product,
        context.target,
        context.optimize,
        root,
    );
    const test_options = b.addOptions();
    test_options.addOption(bool, "metal_only", false);
    test_options.addOption(bool, "riscv_only", true);
    test_options.addOption(bool, "riscv_exhaustive", options.exhaustive);
    test_options.addOption(bool, "riscv_committed_mutations", options.committed_mutations);
    test_options.addOption(bool, "riscv_rigidity_exhaustive", options.rigidity_exhaustive);
    root.addOptions("test_options", test_options);
    return b.addTest(.{ .root_module = root, .filters = test_filter.apply(b, options.filters) });
}

fn createStwoModule(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = graph.create(b, .{
        .product = .{
            .name = product.name,
            .frontend = product.frontend,
            .backend = product.backend,
            .role = .library,
            .protocol_features = product.protocol_features,
        },
        .root_source_file = "src/stwo_riscv_cpu.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(module);
    _ = graph.addProofWireImport(
        b,
        protocol,
        moduleProduct(.library),
        target,
        optimize,
        module,
    );
    integration_graph.addRiscVCpuStack(
        b,
        protocol,
        moduleProduct(.library),
        target,
        optimize,
        module,
    );
    return module;
}

fn moduleProduct(role: graph.Role) graph.Product {
    return .{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = role,
        .protocol_features = product.protocol_features,
    };
}

fn createAdapterModule(
    context: Context,
    protocol: graph.ProtocolModules,
    stwo: *std.Build.Module,
    capabilities: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product,
        .root_source_file = "src/integrations/riscv_cpu/proof_adapter.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(module);
    module.addImport("stwo", stwo);
    module.addImport("riscv_cpu_capabilities", capabilities);
    module.addOptions("build_identity", graph_identity.buildOptions(context.b, context.identity));
    return module;
}

fn createCapabilitiesModule(
    context: Context,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return graph.create(context.b, .{
        .product = product,
        .root_source_file = "src/products/riscv_cpu/capabilities.zig",
        .target = target,
        .optimize = optimize,
    });
}

/// A shared focused-product shell module (`src/products/riscv_shared/*.zig`).
/// The shell files import only `std`, so they need no protocol or facade
/// imports: every product-specific module reaches them through the binding.
/// Zig 0.15 forbids a relative `@import` that leaves the importing module's root
/// directory, so each shared file the CPU root module names must be injected
/// under its own module name rather than reached as `../riscv_shared/*.zig`.
fn createSharedModule(
    context: Context,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return graph.create(context.b, .{
        .product = product,
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
    });
}

fn createOutputTransaction(
    context: Context,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return graph.create(context.b, .{
        .product = product,
        .root_source_file = "src/interop/output_transaction.zig",
        .target = target,
        .optimize = optimize,
    });
}
