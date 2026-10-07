//! Focused test-root construction for the RISC-V CPU product.
const std = @import("std");
const build_identity = @import("../build_identity.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");
const shared_shell = @import("riscv_shared_shell.zig");
const test_filter = @import("riscv_test_filter.zig");

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
    product: graph.Product,
};

/// Every test body `test-riscv-cpu-product` runs under one filter, including
/// suites that were previously only linked and therefore never executed.
pub fn addTests(context: Context) []const test_filter.Suite {
    const b = context.b;
    const stwo = createStwoModule(context);
    const capabilities = createCapabilitiesModule(context);
    const adapter = hostBinding(context).adapterModule(.{
        .protocol = context.protocol,
        .identity = context.identity,
        .stwo = stwo,
        .capabilities = capabilities,
    });
    const test_product = moduleProduct(context, .@"test");
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
    hostBinding(context).addShellImports(root);
    root.addImport(
        "output_transaction",
        outputTransactionModule(context),
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
    const suites = b.allocator.alloc(test_filter.Suite, 4) catch @panic("out of memory");
    suites[0] = .{ .tests = b.addTest(.{ .root_module = root }) };
    suites[1] = .{ .tests = addTestRoot(context, .{}) };
    suites[2] = hostBinding(context).frontendSuite(context.protocol);
    suites[3] = hostBinding(context).moduleSuite(adapter, shared_shell.adapter_test_floor);
    return suites;
}

pub const profile_partition_test_names: []const []const u8 = &.{
    "profiled benchmark timing authority is protocol complete",
    "verified request attempt: disabled capture allocates no task profile",
    "verified request attempt: schema binds duration beside task profile",
    "verified request attempt: complete exact work promotes v3 transactionally",
    "verified request attempt: profiled capture cleans every allocation failure",
    "verified request attempt: snapshot ownership outlives recorder storage",
    "verified request attempt: graph elapsed time cannot exceed proof boundary",
    "verified request attempt: single-worker eligibility is request bounded",
    "verified request attempt: raw phase sum is checked exactly",
    "profiled phase clocks partition guest proof and native verification",
    "request clock and flat graph capture are absent on unprofiled attempts",
    "profiled benchmark binds every measured sample to the new timing authority",
    "ordinary product prove path has no execution policy or recursive call",
    "ordinary public prove API types expose no execution policy parameter",
    "the structural fixture still covers the production adapter",
    "profiled child reports require their distinct internal schema",
};

pub fn addProfilePartitionTests(context: Context) *std.Build.Step.Compile {
    const b = context.b;
    const stwo = createStwoModule(context);
    const capabilities = createCapabilitiesModule(context);
    const adapter = hostBinding(context).adapterModule(.{
        .protocol = context.protocol,
        .identity = context.identity,
        .stwo = stwo,
        .capabilities = capabilities,
    });
    return b.addTest(.{
        .root_module = adapter,
        .filters = test_filter.apply(b, profile_partition_test_names),
    });
}
/// Names which suites a `src/tests.zig` binary compiles and runs; positional
/// booleans would not reveal which sweep a call site pays for.
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
pub fn addCoreProverTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{ .exhaustive = true });
}
pub fn addExhaustiveTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{
        .exhaustive = true,
        .committed_mutations = true,
        .rigidity_exhaustive = true,
    });
}
pub fn addRigidityTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{
        .exhaustive = true,
        .rigidity_exhaustive = true,
        .filters = &.{"witness rigidity"},
    });
}

pub fn addAirSatisfactionExportTests(context: Context) *std.Build.Step.Compile {
    return addTestRoot(context, .{
        .exhaustive = true,
        .committed_mutations = true,
        .filters = &.{ "committed trace export", "uniqueness IR: emit every family" },
    });
}

pub fn addTestRoot(context: Context, options: TestRoot) *std.Build.Step.Compile {
    const b = context.b;
    const test_product = moduleProduct(context, .@"test");
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

/// Builds a single cross-module test file as its own root.  Focused recursion
/// iteration must not semantically analyse the entire exhaustive RISC-V test
/// corpus merely because Zig applies a runtime name filter after compilation.
pub fn addFocusedTestRoot(
    context: Context,
    root_source_file: []const u8,
    filters: []const []const u8,
) *std.Build.Step.Compile {
    const b = context.b;
    const test_product = moduleProduct(context, .@"test");
    const root = graph.create(b, .{
        .product = test_product,
        .root_source_file = root_source_file,
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
    return b.addTest(.{
        .root_module = root,
        .filters = test_filter.apply(b, filters),
    });
}

fn moduleProduct(context: Context, role: graph.Role) graph.Product {
    return riscv_cpu_modules.roleProduct(context.product, role);
}

fn hostBinding(context: Context) shared_shell.Binding {
    return riscv_cpu_modules.binding(
        context.b,
        context.product,
        context.target,
        context.optimize,
    );
}

fn createCapabilitiesModule(context: Context) *std.Build.Module {
    return riscv_cpu_modules.capabilities(
        context.b,
        context.product,
        context.target,
        context.optimize,
    );
}

fn outputTransactionModule(context: Context) *std.Build.Module {
    return riscv_cpu_modules.outputTransaction(
        context.b,
        context.product,
        context.target,
        context.optimize,
    );
}

fn createStwoModule(context: Context) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = moduleProduct(context, .library),
        .root_source_file = "src/stwo_riscv_cpu.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    _ = graph.addProofWireImport(
        context.b,
        context.protocol,
        moduleProduct(context, .library),
        context.target,
        context.optimize,
        module,
    );
    integration_graph.addRiscVCpuStack(
        context.b,
        context.protocol,
        moduleProduct(context, .library),
        context.target,
        context.optimize,
        module,
    );
    return module;
}
