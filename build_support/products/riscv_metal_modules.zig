//! Module construction shared by the Metal product and its focused test lanes.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const metal_aot = @import("../backends/metal_aot.zig");
const build_identity = @import("../build_identity.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const shared_shell = @import("riscv_shared_shell.zig");

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};

pub fn productionRootModule(
    context: Context,
    product: graph.Product,
    aot_bundle: metal_aot.ExternalBundle,
) *std.Build.Module {
    return rootModule(
        context,
        product,
        product,
        "src/products/riscv_metal/main.zig",
        aot_bundle,
    );
}

pub fn rootModule(
    context: Context,
    product: graph.Product,
    identity_product: graph.Product,
    root_source_file: []const u8,
    aot_bundle: metal_aot.ExternalBundle,
) *std.Build.Module {
    const b = context.b;
    const stwo = createFacadeModule(context, product, roleProduct(product, .library));
    const capabilities = capabilitiesModule(context, product);
    // The engine-generic adapter keeps the historical `riscv_cpu_capabilities`
    // import name, bound here to this product's Metal capability file.
    const adapter = binding(context, product).adapterModule(.{
        .protocol = context.protocol,
        .identity = context.identity,
        .stwo = stwo,
        .capabilities = capabilities,
    });
    const root = graph.create(b, .{
        .product = identity_product,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_riscv_metal", stwo);
    root.addImport("riscv_adapter", adapter);
    root.addImport("riscv_capabilities", capabilities);
    root.addImport("riscv_cpu_capabilities", capabilities);
    binding(context, product).addShellImports(root);
    root.addImport("output_transaction", binding(context, product).leafModule(
        "src/interop/output_transaction.zig",
    ));
    root.addOptions("metal_aot_config", aot_bundle.addOptions(b));
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    root.addOptions(
        "product_identity",
        productIdentityOptions(context, identity_product, aot_bundle),
    );
    return root;
}

pub fn productIdentityOptions(
    context: Context,
    identity_product: graph.Product,
    aot_bundle: metal_aot.ExternalBundle,
) *std.Build.Step.Options {
    return graph_identity.productOptionsWithRuntime(
        context.b,
        context.identity,
        identity_product,
        context.target,
        context.optimize,
        metal.authenticatedAotIdentity(
            context.b,
            &aot_bundle.manifest_sha256_hex,
        ),
    );
}

pub fn capabilitiesModule(context: Context, product: graph.Product) *std.Build.Module {
    return binding(context, product).leafModule(
        "src/products/riscv_metal/capabilities.zig",
    );
}

pub fn binding(context: Context, product: graph.Product) shared_shell.Binding {
    return .{
        .b = context.b,
        .product = product,
        .target = context.target,
        .optimize = context.optimize,
    };
}

pub fn createModule(
    context: Context,
    product: graph.Product,
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
    const proof_wire = graph.addProofWireImport(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
        module,
    );
    const dependencies = createDependencies(context, logical_product, proof_wire);
    module.addImport("stwo_metal_backend", dependencies.metal_backend);
    module.addImport("stwo_riscv_frontend", dependencies.frontend);
    module.addImport("stwo_riscv_metal_integration", dependencies.integration);
    _ = product;
    return module;
}

pub fn createFacadeModule(
    context: Context,
    product: graph.Product,
    logical_product: graph.Product,
) *std.Build.Module {
    const dependencies = createDependencies(context, logical_product, null);
    const facade = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/products/riscv_metal/root.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(facade);
    facade.addImport("stwo_riscv_frontend", dependencies.frontend);
    facade.addImport("stwo_riscv_metal_integration", dependencies.integration);
    addInteropImports(context, product, facade, dependencies.frontend);
    return facade;
}

fn addInteropImports(
    context: Context,
    product: graph.Product,
    facade: *std.Build.Module,
    frontend: *std.Build.Module,
) void {
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");

    facade.addImport("interop_postcard", postcard);
    facade.addImport("interop_riscv_artifact", binding(context, product).leafModule(
        "src/interop/riscv_artifact.zig",
    ));
}

const Dependencies = struct {
    frontend: *std.Build.Module,
    metal_backend: *std.Build.Module,
    integration: *std.Build.Module,
};

fn createDependencies(
    context: Context,
    logical_product: graph.Product,
    proof_wire: ?*std.Build.Module,
) Dependencies {
    const frontend = graph.createRiscVFrontend(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
        proof_wire,
    );
    const metal_backend = graph.createMetalBackend(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
    );
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

pub fn roleProduct(product: graph.Product, role: graph.Role) graph.Product {
    return shared_shell.roleProduct(product, role);
}
