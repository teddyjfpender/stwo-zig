//! Dedicated streamed Ethereum segment proof product wiring.

const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const riscv_cpu_modules = @import("riscv_cpu_modules.zig");

pub fn add(context: anytype, product: graph.Product) void {
    const role_product = riscv_cpu_modules.roleProduct(product, .benchmark);
    addCanonicalStreamTools(context, role_product);
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

/// Canonical full-width BLAKE3 block route. The measurement and installed
/// products share the same roots; no second proving implementation is introduced.
fn addCanonicalStreamTools(context: anytype, product: graph.Product) void {
    const Tool = struct { name: []const u8, root: []const u8, description: []const u8 };
    for ([_]Tool{
        .{ .name = "stwo-ethereum-block-stream", .root = "src/frontends/riscv/ethereum_block_stream.zig", .description = "Build canonical BLAKE3 Ethereum execution and recursive root proving" },
        .{ .name = "stwo-ethereum-block-verify", .root = "src/frontends/riscv/ethereum_block_verify.zig", .description = "Build canonical Ethereum root verification with a receiver-owned key pin" },
        .{ .name = "stwo-ethereum-block-exact-verify", .root = "src/frontends/riscv/ethereum_block_exact_verify.zig", .description = "Build canonical exact-count forest verification with a receiver-owned roster pin" },
        .{ .name = "stwo-ethereum-block-v4-cpu-produce", .root = "src/frontends/riscv/ethereum_block_v4_cpu_produce.zig", .description = "Build staged canonical CPU block-v4 proof bundle producer" },
        .{ .name = "stwo-ethereum-block-v4-cpu-verify", .root = "src/frontends/riscv/ethereum_block_v4_cpu_verify.zig", .description = "Build detached canonical CPU block-v4 proof bundle verifier" },
        .{ .name = "stwo-ethereum-block-v5-cpu-produce", .root = "src/frontends/riscv/ethereum_block_v5_cpu_produce.zig", .description = "Build streaming CPU block-v5 all-family producer and fresh complete detached receiver" },
        .{ .name = "stwo-ethereum-block-v5-cpu-verify", .root = "src/frontends/riscv/ethereum_block_v5_cpu_verify.zig", .description = "Build fresh standalone complete block-v5 CPU bundle verifier" },
        .{ .name = "stwo-ethereum-block-v4-candidate-roster", .root = "src/frontends/riscv/block_v4_cpu_candidate_roster.zig", .description = "Build read-only candidate native-key roster proposal tool" },
        .{ .name = "stwo-ethereum-block-v4-geometry-gate", .root = "src/frontends/riscv/block_v4_cpu_geometry_gate.zig", .description = "Build read-only actual first-round CPU block-v4 geometry scanner" },
        .{ .name = "stwo-ethereum-block-v4-smoke-fixture", .root = "src/frontends/riscv/block_v4_cpu_smoke_fixture.zig", .description = "Build small real-I/O and Keccak CPU block-v4 smoke fixture writer" },
    }) |tool| {
        const root = graph.create(context.b, .{
            .product = product,
            .root_source_file = tool.root,
            .target = context.target,
            .optimize = context.optimize,
        });
        context.protocol.addImports(root);
        // Reuse the canonical frontend's postcard/proof-wire module identities.
        _ = graph.addRiscVFrontendImport(context.b, context.protocol, product, context.target, context.optimize, root);
        _ = graph.addCpuBackendImport(context.b, context.protocol, product, context.target, context.optimize, root);
        root.link_libc = true;
        const executable = context.b.addExecutable(.{ .name = tool.name, .root_module = root });
        const install = context.b.addInstallArtifact(executable, .{});
        context.b.step(tool.name, tool.description).dependOn(&install.step);
    }
}
