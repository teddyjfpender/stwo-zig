//! Executable construction for the CPU product and its diagnostic commands.
const std = @import("std");
const build_identity = @import("../build_identity.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");

pub const product = graph.Product{
    .name = "stwo-riscv-cpu",
    .frontend = .riscv,
    .backend = .cpu,
    .role = .cli,
    .protocol_features = "rv32im-zkvm-v1+sail-authoritative+lifted-pcs-v1" ++
        "+rv32im-zkvm-poseidon2-v1+csp-ecdsa-typed-recovery-v1",
};
pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};

pub fn addTraceExecutable(
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
pub const Observer = enum {
    pc_hotspot,
    function_value,
    legacy_semantics,
    memcpy_hotspot,
    memcpy_admission,

    fn spec(self: Observer) struct { source: []const u8, binary: []const u8 } {
        return switch (self) {
            .pc_hotspot => .{ .source = "src/tools/riscv/pc_hotspot/main.zig", .binary = "riscv-pc-hotspot-observer" },
            .function_value => .{ .source = "src/tools/riscv/function_value/main.zig", .binary = "riscv-function-value-observer" },
            .legacy_semantics => .{ .source = "src/tools/riscv/analyze_legacy_semantics/main.zig", .binary = "riscv-analyze-legacy-semantic-observer" },
            .memcpy_hotspot => .{ .source = "src/tools/riscv/memcpy_hotspot/main.zig", .binary = "riscv-memcpy-hotspot-observer" },
            .memcpy_admission => .{ .source = "src/tools/riscv/memcpy_admission/main.zig", .binary = "riscv-memcpy-admission-observer" },
        };
    }
};

pub fn addObserver(
    context: Context,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    observer: Observer,
) *std.Build.Step.Compile {
    const spec = observer.spec();
    const b = context.b;
    const root = graph.create(b, .{
        .product = product,
        .root_source_file = spec.source,
        .target = target,
        .optimize = optimize,
    });
    context.protocol.addImports(root);
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        product,
        target,
        optimize,
        root,
    );
    root.addOptions(
        "build_identity",
        graph_identity.buildOptions(b, context.identity),
    );
    return b.addExecutable(.{
        .name = spec.binary,
        .root_module = root,
    });
}

pub fn addExecutable(
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

pub fn addRecursiveCspProducer(context: Context) *std.Build.Step.Compile {
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
pub fn addRecursionShapeInspector(context: Context) *std.Build.Step.Compile {
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
