//! Dedicated streamed Ethereum segment proof product wiring.

const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");

pub fn add(context: anytype, product: graph.Product) void {
    const role_product = riscv_cpu_modules.roleProduct(product, .benchmark);
    const root = graph.create(context.b, .{
        .product = role_product,
        .root_source_file = "src/products/riscv_cpu/ethereum_block_proof_main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    integration_graph.addRiscVCpuStack(
        context.b,
        context.protocol,
        role_product,
        context.target,
        context.optimize,
        root,
    );
    root.addOptions(
        "build_identity",
        graph_identity.buildOptions(context.b, context.identity),
    );
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            context.b,
            context.identity,
            role_product,
            context.target,
            context.optimize,
        ),
    );
    const executable = context.b.addExecutable(.{
        .name = "stwo-ethereum-block-proof",
        .root_module = root,
    });
    const install = context.b.addInstallArtifact(executable, .{});
    context.b.step(
        "stwo-ethereum-block-proof",
        "Build the streamed Ethereum segment proof producer/verifier",
    ).dependOn(&install.step);
}
