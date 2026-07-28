//! Build ownership for the official Cairo + CPU/SIMD product.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const cairo_oracle_gate = @import("cairo_cpu/oracle_gate.zig");
const cairo_support = @import("cairo_support.zig");
const cairo_witness_cpu_aot = @import("cairo_witness_cpu_aot.zig");
const cairo_vm_adapter = @import("cairo_cpu/vm_adapter.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const policy = @import("../graph/product.zig");

const protocol_features =
    cairo_support.protocol_features ++
    "+authenticated-witness-cpu-aot-v1";

const source_closure = policy.SourceClosure{
    .entry_roots = &.{
        "src/products/cairo_cpu/main.zig",
        "src/stwo_cairo_cpu.zig",
    },
    .named_imports = &.{
        .{ .name = "cairo_product", .source = "src/products/cairo/shared/mod.zig" },
        .{ .name = "stwo_cairo", .source = "src/stwo_cairo_cpu.zig" },
        .{ .name = "stwo_cairo_cpu", .source = "src/stwo_cairo_cpu.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cairo_frontend", .source = "src/frontends/cairo/mod.zig" },
        .{ .name = "stwo_cairo_cpu_integration", .source = "src/integrations/cairo_cpu/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
    },
    .generated_imports = &.{
        "cairo_witness_cpu_aot",
        "product_identity",
    },
    .allowed_files = &.{
        "src/stwo_cairo_cpu.zig",
        "src/interop/atomic_file.zig",
        "src/interop/bzip2.zig",
        "src/interop/output_transaction.zig",
    },
    .allowed_prefixes = &.{
        "src/backend",
        "src/backends/cpu_scalar",
        "src/core",
        "src/frontends/cairo",
        "src/integrations/cairo_cpu",
        "src/products/cairo",
        "src/products/cairo_cpu",
        "src/prover",
    },
    .forbidden_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
        "cuda",
    },
};

pub const descriptor = policy.Descriptor{
    .product = product(.cli),
    .state = .released,
    .target_support = .any,
    .build_step = "stwo-cairo-cpu",
    .test_step = "test-cairo-cpu-product",
    .executable = "stwo-cairo-cpu",
    .installed_artifacts = &.{
        "stwo-cairo-cpu",
        "stwo-cairo-vm-adapter",
        "share/stwo-zig/cairo/official/all_opcodes.params.json",
        "share/stwo-zig/cairo/official/all_builtins.params.json",
    },
    .release_gates = &.{
        "test-cairo-cpu-product",
        "test-cairo-cpu-oracle",
    },
    .dependencies = .{ .module_roots = source_closure.entry_roots },
    .source_closure = source_closure,
};

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};

pub fn addProduct(context: Context) void {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid Cairo CPU descriptor: {s}",
        .{@errorName(err)},
    );
    const stwo = createStwoModule(context, .library);
    const shared = createSharedProductModule(context, .library, stwo);
    const witness_aot = cairo_witness_cpu_aot.createModule(
        context.b,
        context.target,
        context.optimize,
        stwo,
    );
    const root = createProductModule(
        context,
        descriptor.product,
        stwo,
        shared,
        witness_aot,
    );
    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the focused official Cairo CPU/SIMD proof CLI",
    );
    cairo_support.linkBzip2(context.b, installed.executable);
    installed.build_step.dependOn(cairo_vm_adapter.addInstall(context.b));
    cairo_support.installProfile(context.b, installed.build_step);

    const test_stwo = createStwoModule(context, .@"test");
    const test_witness_aot = cairo_witness_cpu_aot.createModule(
        context.b,
        context.target,
        context.optimize,
        test_stwo,
    );
    const test_root = createProductModule(
        context,
        product(.@"test"),
        test_stwo,
        createSharedProductModule(context, .@"test", test_stwo),
        test_witness_aot,
    );
    const tests = context.b.addTest(.{ .root_module = test_root });
    cairo_support.linkBzip2(context.b, tests);
    const test_step = context.b.step(
        descriptor.test_step.?,
        "Test the Cairo CPU product, profile, and command contract",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);

    const help = context.b.addRunArtifact(installed.executable);
    help.addArg("--help");
    test_step.dependOn(&help.step);
    const capabilities = context.b.addRunArtifact(installed.executable);
    capabilities.addArg("capabilities");
    test_step.dependOn(&capabilities.step);
    const identity = context.b.addRunArtifact(installed.executable);
    identity.addArg("identity");
    test_step.dependOn(&identity.step);

    const closure = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure.step);
    cairo_oracle_gate.add(context.b, installed.executable);
}

/// Builds an uninstalled CPU authority used by cross-backend parity gates.
pub fn addReferenceExecutable(
    context: Context,
) *std.Build.Step.Compile {
    const stwo = createStwoModule(context, .gate);
    const shared = createSharedProductModule(context, .gate, stwo);
    const witness_aot = cairo_witness_cpu_aot.createModule(
        context.b,
        context.target,
        context.optimize,
        stwo,
    );
    const executable = context.b.addExecutable(.{
        .name = "stwo-cairo-cpu-reference",
        .root_module = createProductModule(
            context,
            product(.gate),
            stwo,
            shared,
            witness_aot,
        ),
    });
    cairo_support.linkBzip2(context.b, executable);
    return executable;
}

fn createStwoModule(
    context: Context,
    role: graph.Role,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/stwo_cairo_cpu.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    integration_graph.addCairoCpuStack(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    return module;
}

fn createProductModule(
    context: Context,
    product_descriptor: graph.Product,
    stwo: *std.Build.Module,
    shared: *std.Build.Module,
    witness_aot: *std.Build.Module,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/products/cairo_cpu/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo_cairo_cpu", stwo);
    root.addImport("cairo_product", shared);
    root.addImport("cairo_witness_cpu_aot", witness_aot);
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            context.b,
            context.identity,
            product_descriptor,
            context.target,
            context.optimize,
        ),
    );
    return root;
}

fn createSharedProductModule(
    context: Context,
    role: graph.Role,
    stwo: *std.Build.Module,
) *std.Build.Module {
    return cairo_support.createProductSupportModule(
        context.b,
        context.target,
        context.optimize,
        product(role),
        stwo,
    );
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-cairo-cpu",
        .frontend = .cairo,
        .backend = .cpu,
        .role = role,
        .protocol_features = protocol_features,
    };
}

test "Cairo CPU is a focused released product" {
    try descriptor.validate();
    try std.testing.expect(descriptor.isConstructible());
    try std.testing.expectEqual(policy.State.released, descriptor.state);
}
