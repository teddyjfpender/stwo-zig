//! Build ownership for the RV32IM frontend on the fail-closed Metal backend.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

const product = graph.Product{
    .name = "stwo-riscv-metal",
    .frontend = .riscv,
    .backend = .metal,
    .role = .cli,
    .protocol_features = "rv32im-zkvm-v1+lifted-pcs-v1+metal-runtime-v1",
};

const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{
        "src/riscv_metal_bench_cli.zig",
        "src/products/riscv_metal/root.zig",
        "src/integrations/riscv_metal/mod.zig",
        "src/tests/riscv/metal_backend_test.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_metal_backend", .source = "src/backends/metal_surface.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
        .{ .name = "stwo_riscv_frontend", .source = "src/frontends/riscv/mod.zig" },
        .{ .name = "stwo_riscv_metal", .source = "src/products/riscv_metal/root.zig" },
        .{ .name = "stwo_riscv_metal_integration", .source = "src/integrations/riscv_metal/mod.zig" },
    },
    .allowed_files = &.{
        "src/riscv_metal_bench_cli.zig",
        "src/backends/metal_surface.zig",
        "src/products/riscv_metal/root.zig",
        "src/tests/riscv/metal_backend_test.zig",
    },
    .allowed_prefixes = &.{
        "src/core",
        "src/backend",
        "src/backends/cpu_scalar",
        "src/backends/metal",
        "src/prover",
        "src/frontends/riscv",
        "src/integrations/riscv_cpu",
        "src/integrations/riscv_metal",
        "src/tools/riscv",
    },
    .required_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
    },
    .forbidden_dynamic_dependencies = &.{"cuda"},
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
    .state = .parity_gated,
    .target_support = .macos,
    .unsupported_target_reason = "the Metal backend requires a macOS target and Apple Metal SDK",
    .build_step = "stwo-riscv-metal",
    .test_step = "test-riscv-metal",
    .executable = "stwo-zig-riscv-metal",
    .installed_artifacts = &.{"stwo-zig-riscv-metal"},
    .compatibility_aliases = &.{"riscv-metal-bench"},
    .release_gates = &.{ "test-riscv-metal", "metal-test", "riscv-release-gate" },
    .benchmark_step = "riscv-metal-bench",
    .dependencies = .{
        .module_roots = source_closure.entry_roots,
        .external_dependencies = &.{
            "Foundation.framework",
            "Metal.framework",
            "libobjc",
        },
    },
    .source_closure = source_closure,
};

pub fn addProduct(context: Context) void {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid RISC-V Metal descriptor: {s}",
        .{@errorName(err)},
    );
    if (!descriptor.isAvailableOn(context.target.result.os.tag)) {
        product_policy.registerUnavailable(context.b, descriptor, context.target.result.os.tag);
        return;
    }

    const root = createModule(context, product, "src/riscv_metal_bench_cli.zig");
    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the focused RV32IM Metal proof CLI",
    );
    metal.linkRuntime(context.b, installed.executable);

    const benchmark_product = graph.Product{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = .benchmark,
        .protocol_features = product.protocol_features,
    };
    const benchmark = graph_install.executable(
        context.b,
        "riscv-metal-bench",
        createModule(context, benchmark_product, "src/riscv_metal_bench_cli.zig"),
        descriptor.benchmark_step.?,
        "Build the compatible RV32IM Metal benchmark",
    );
    metal.linkRuntime(context.b, benchmark.executable);

    const stwo_tests = createFacadeModule(
        context,
        testProduct(),
    );
    const integration_tests = context.b.addTest(.{ .root_module = stwo_tests });
    metal.linkRuntime(context.b, integration_tests);
    const proof_test_module = createModule(
        context,
        testProduct(),
        "src/tests/riscv/metal_backend_test.zig",
    );
    const stwo = createFacadeModule(
        context,
        .{
            .name = product.name,
            .frontend = product.frontend,
            .backend = product.backend,
            .role = .library,
            .protocol_features = product.protocol_features,
        },
    );
    proof_test_module.addImport("stwo_riscv_metal", stwo);
    const proof_tests = context.b.addTest(.{
        .root_module = proof_test_module,
    });
    metal.linkRuntime(context.b, proof_tests);

    const test_step = context.b.step(
        descriptor.test_step.?,
        "Test RV32IM Metal engine ownership and end-to-end proof parity",
    );
    test_step.dependOn(&context.b.addRunArtifact(integration_tests).step);
    test_step.dependOn(&context.b.addRunArtifact(proof_tests).step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);
}

fn createModule(
    context: Context,
    logical_product: graph.Product,
    root_source_file: []const u8,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    const dependencies = createDependencies(context, logical_product);
    module.addImport("stwo_metal_backend", dependencies.metal_backend);
    module.addImport("stwo_riscv_frontend", dependencies.frontend);
    module.addImport("stwo_riscv_metal_integration", dependencies.integration);
    return module;
}

fn createFacadeModule(
    context: Context,
    logical_product: graph.Product,
) *std.Build.Module {
    const dependencies = createDependencies(context, logical_product);
    const facade = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/products/riscv_metal/root.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(facade);
    facade.addImport("stwo_riscv_frontend", dependencies.frontend);
    facade.addImport("stwo_riscv_metal_integration", dependencies.integration);
    return facade;
}

const Dependencies = struct {
    frontend: *std.Build.Module,
    metal_backend: *std.Build.Module,
    integration: *std.Build.Module,
};

fn createDependencies(
    context: Context,
    logical_product: graph.Product,
) Dependencies {
    const frontend = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/frontends/riscv/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(frontend);

    const metal_backend = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/backends/metal_surface.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(metal_backend);

    const integration = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/integrations/riscv_metal/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(integration);
    integration.addImport("stwo_metal_backend", metal_backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    return .{
        .frontend = frontend,
        .metal_backend = metal_backend,
        .integration = integration,
    };
}

fn testProduct() graph.Product {
    return .{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = .@"test",
        .protocol_features = product.protocol_features,
    };
}

test "descriptor requires Metal and explicitly excludes CUDA" {
    try descriptor.validate();
    try std.testing.expectEqual(product_policy.State.parity_gated, descriptor.state);
    try std.testing.expectEqual(product_policy.TargetSupport.macos, descriptor.target_support);
    try std.testing.expectEqualStrings("stwo-zig-riscv-metal", descriptor.executable.?);
    try std.testing.expectEqualStrings("cuda", source_closure.forbidden_dynamic_dependencies[0]);
}
