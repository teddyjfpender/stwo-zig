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
        .root_source_file = "src/waist/core/mod.zig",
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
        .root_source_file = "src/products/stwo/prover/root.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    protocol.addImports(prover);
    const stwo = context.b.addModule("stwo", .{
        .root_source_file = context.b.path("src/products/stwo/root.zig"),
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
    _ = graph.addArtifactStoreImport(
        context.b,
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
    const native_cuda = integration_graph.addNativeCudaImport(
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
    integration_graph.addEthereumCpuCompatibility(context.b, context.target, context.optimize, stwo);
    const cairo_frontend = graph.addCairoFrontendImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    stwo.addImport("stwo_circuit_recursion_wire", stwo.import_table.get("stwo_circuit_recursion_wire") orelse graph.createCircuitRecursionWire(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cairo_frontend,
    ));
    _ = integration_graph.addCairoCudaImport(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cuda_backend,
        cairo_frontend,
        native_cuda,
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
    graph.addFacadeSupportImports(
        context.b,
        protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
        graph.FacadeSupport.root,
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
        .root_source_file = context.b.path("src/products/stwo/root.zig"),
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
    _ = graph.addArtifactStoreImport(
        context.b,
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
    const cdc = @import("package_dependencies.zig");
    const consumer_step = context.b.step("test-cdc-stwo-core", "Run registered consumer-owned Core contracts");
    const source_check = context.b.addSystemCommand(&.{ "python3", "scripts/repo/check_package_workspace.py" });
    source_check.setCwd(context.b.path("."));
    for (cdc.coreConsumers(context.b)) |registration| {
        if (!std.mem.startsWith(u8, registration.id, "package:")) @panic("unsupported consumer kind");
        const owner_name = registration.id["package:".len..];
        const owner = stwo.import_table.get(owner_name) orelse @panic("missing actual consumer module");
        const provider = owner.import_table.get("stwo_core") orelse @panic("consumer missing canonical Core");
        if (provider != prover.protocol.core) @panic("consumer/provider Core module identity mismatch");
        const root = graph.create(context.b, .{ .product = sdkProduct(), .root_source_file = registration.root, .target = context.target, .optimize = context.optimize });
        for (registration.imports) |name| root.addImport(name, stwo.import_table.get(name) orelse @panic("unbound consumer public import"));
        const name = context.b.fmt("cdc-stwo-core-{s}-{s}", .{ owner_name, @tagName(context.optimize) });
        const artifact = context.b.addTest(.{ .name = name, .root_module = root });
        artifact.step.dependOn(&source_check.step);
        const run = context.b.addRunArtifact(artifact);
        run.setCwd(context.b.path("."));
        consumer_step.dependOn(&run.step);
        const install = context.b.addInstallArtifact(artifact, .{ .dest_sub_path = name });
        consumer_step.dependOn(&install.step);
    }

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
    const native_cuda = integration_graph.addNativeCudaImport(
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
    integration_graph.addEthereumCpuCompatibility(context.b, context.target, context.optimize, stwo);
    const cairo_frontend = graph.addCairoFrontendImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
    );
    stwo.addImport("stwo_circuit_recursion_wire", stwo.import_table.get("stwo_circuit_recursion_wire") orelse graph.createCircuitRecursionWire(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cairo_frontend,
    ));
    _ = integration_graph.addCairoCudaImport(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        cuda_backend,
        cairo_frontend,
        native_cuda,
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
    graph.addFacadeSupportImports(
        context.b,
        prover.protocol,
        sdkProduct(),
        context.target,
        context.optimize,
        stwo,
        graph.FacadeSupport.root,
    );

    const consumer_root = consumer(context.b, prover.protocol, .{
        .root_source_file = context.b.path("src/products/stwo/tests/public_modules.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    consumer_root.addImport("stwo_prover", prover.module);
    consumer_root.addImport("stwo", stwo);
    const sdk_consumer = context.b.addExecutable(.{ .name = "sdk-consumer-smoke", .root_module = consumer_root });
    const sdk_run = context.b.addRunArtifact(sdk_consumer);
    sdk_run.has_side_effects = true;

    const downstream = context.b.addSystemCommand(&.{
        "python3",
        "scripts/repo/check_downstream_package.py",
        "--repo",
        context.b.build_root.path.?,
    });
    downstream.has_side_effects = true;
    downstream.step.dependOn(&sdk_run.step);
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
