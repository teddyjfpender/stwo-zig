//! Build ownership for the RV64 recursion tools: the leaf wrap of one RV64
//! Ethereum batch proof into a circuit proof, the fold to a root, and the
//! root receiver. They link both the RISC-V CPU stack and the circuit
//! recursion stack, so they live beside the RISC-V CPU product rather than
//! inside either product's source closure.
const std = @import("std");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const circuit_product = @import("circuit_recursion_cpu.zig");
const riscv_cpu_tests = @import("riscv_cpu_tests.zig");
const test_filter = @import("riscv_test_filter.zig");

const roots = [_]struct { step: []const u8, source: []const u8, description: []const u8 }{
    .{ .step = "rv64-recursion", .source = "src/integrations/riscv_cpu/rv64_recursion_main.zig", .description = "Build the RV64 recursion tools: wrap batch proofs into circuit leaves, fold them to one root, verify the root" },
};

pub fn addProduct(context: circuit_product.Context, product: graph.Product) void {
    for (roots) |spec| {
        const root = createRoot(context, product, spec.source);
        const executable = context.b.addExecutable(.{ .name = spec.step, .root_module = root });
        const install = context.b.addInstallArtifact(executable, .{});
        context.b.step(spec.step, spec.description).dependOn(&install.step);
    }
    for ([_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "test-riscv64-recursion-circuit", .source = "src/integrations/riscv_cpu/rv64_recursion_circuit_test_root.zig" },
        .{ .name = "test-riscv64-word16-execution-circuit", .source = "src/integrations/riscv_cpu/rv64_word16_execution_circuit_test_root.zig" },
    }) |spec| {
        const tests = context.b.addTest(.{ .root_module = createRoot(context, product, spec.source) });
        const run = context.b.addRunArtifact(tests);
        run.setCwd(context.b.path("."));
        context.b.step(spec.name, "Qualify native and circuit-lane execution authorities").dependOn(&run.step);
    }
}

fn createRoot(context: circuit_product.Context, product: graph.Product, source: []const u8) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = product,
        .root_source_file = source,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    _ = graph.addProofWireImport(context.b, context.protocol, product, context.target, context.optimize, root);
    integration_graph.addRiscVCpuStack(context.b, context.protocol, product, context.target, context.optimize, root);
    circuit_product.addCircuitStack(context, product, root);
    return root;
}

comptime {
    _ = riscv_cpu_tests;
    _ = test_filter;
}
