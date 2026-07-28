//! Public library products and the aggregate downstream compatibility module.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const construction_observer = @import("../graph/construction_observer.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const core_product = @import("core.zig");
const prover_product = @import("prover.zig");

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: ?build_identity.Identity = null,
};

pub const Result = struct {
    stwo: *std.Build.Module,
    protocol: graph.ProtocolModules,
};

/// Declares the package's public import surface without constructing product
/// tests, tools, gates, or install steps. Root build dispatch uses this path so
/// focused commands configure only their delegated product graph.
pub fn addPublicModules(context: Context) Result {
    const core = graph.addPublic(context.b, "stwo_core", .{
        .product = graph.coreProduct(.library),
        .root_source_file = "src/core/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    const protocol = graph.createProtocolModules(
        context.b,
        core,
        context.target,
        context.optimize,
    );
    const prover = graph.addPublic(context.b, "stwo_prover", .{
        .product = graph.proverProduct(.library),
        .root_source_file = "src/products/prover/root.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    protocol.addImports(prover);
    const stwo = context.b.addModule("stwo", .{
        .root_source_file = context.b.path("src/stwo.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    protocol.addImports(stwo);
    const proof_wire = graph.addProofWireImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    const metal_session = graph.addMetalSessionImport(
        context.b,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    const cpu_backend = graph.addCpuBackendImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    const native_examples = graph.addNativeExamplesImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        proof_wire,
        stwo,
    );
    const metal_backend = graph.addMetalBackendImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        stwo,
    );
    const cuda_backend = graph.addCudaBackendImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    _ = integration_graph.addNativeCudaImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cuda_backend,
        native_examples,
        proof_wire,
        stwo,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    _ = integration_graph.addRiscVCpuImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        riscv_frontend,
        stwo,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    _ = integration_graph.addCairoCpuImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        cairo_frontend,
        stwo,
    );
    _ = integration_graph.addCairoMetalImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        metal_backend,
        cairo_frontend,
        metal_session,
        stwo,
    );
    return .{ .stwo = stwo, .protocol = protocol };
}

pub fn addProducts(context: Context) Result {
    const identity = context.identity orelse @panic("library products require source identity");
    const core = core_product.addProduct(.{
        .b = context.b,
        .target = context.target,
        .optimize = context.optimize,
        .identity = identity,
    });
    construction_observer.recordProduct(context.b, graph.coreProduct(.library));
    const prover = prover_product.addProduct(.{
        .b = context.b,
        .target = context.target,
        .optimize = context.optimize,
        .core = core.module,
        .identity = identity,
    });
    construction_observer.recordProduct(context.b, graph.proverProduct(.library));
    const stwo = context.b.addModule("stwo", .{
        .root_source_file = context.b.path("src/stwo.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    construction_observer.recordProduct(context.b, sdkProduct());
    prover.protocol.addImports(stwo);
    const proof_wire = graph.addProofWireImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    const metal_session = graph.addMetalSessionImport(
        context.b,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    const cpu_backend = graph.addCpuBackendImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    const native_examples = graph.addNativeExamplesImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        proof_wire,
        stwo,
    );
    const metal_backend = graph.addMetalBackendImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        stwo,
    );
    const cuda_backend = graph.addCudaBackendImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    _ = integration_graph.addNativeCudaImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cuda_backend,
        native_examples,
        proof_wire,
        stwo,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    _ = integration_graph.addRiscVCpuImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        riscv_frontend,
        stwo,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    _ = integration_graph.addCairoCpuImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cpu_backend,
        cairo_frontend,
        stwo,
    );
    _ = integration_graph.addCairoMetalImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        metal_backend,
        cairo_frontend,
        metal_session,
        stwo,
    );

    const downstream = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_downstream_package.py",
        "--repo",
        context.b.build_root.path.?,
    });
    const downstream_step = context.b.step(
        "test-downstream-modules",
        "Compile and run a clean external consumer of stwo_core, stwo_prover, and stwo",
    );
    downstream_step.dependOn(&downstream.step);
    prover.test_step.dependOn(&downstream.step);

    return .{ .stwo = stwo, .protocol = prover.protocol };
}

fn sdkProduct() graph.Product {
    return .{
        .name = "stwo",
        .frontend = .aggregate,
        .backend = .contracts,
        .role = .library,
        .protocol_features = "aggregate-sdk-v1",
    };
}

pub fn consumer(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    options: std.Build.Module.CreateOptions,
) *std.Build.Module {
    const module = b.createModule(options);
    protocol.addImports(module);
    return module;
}
