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
    .{ .step = "rv64-gkr-circuit-cost", .source = "src/integrations/riscv_cpu/rv64_gkr_circuit_cost_main.zig", .description = "Inspect actual GKR verifier circuit graph cost on native-verified mini-AIR bundles" },
    .{ .step = "rv64-om31-cost", .source = "src/integrations/riscv_cpu/rv64_om31_cost_main.zig", .description = "Measure isolated OM31 native and circuit arithmetic, no protocol migration" },
    .{ .step = "rv64-word16-recursion-shape", .source = "src/integrations/riscv_cpu/rv64_word16_recursion_shape_main.zig", .description = "Inspect native-verified Word16 shapes without constructing a recursive circuit" },
    .{ .step = "rv64-v3-truth-leaf", .source = "src/integrations/riscv_cpu/rv64_v3_truth_leaf_main.zig", .description = "Wrap the v3 truth proofs (SHA-256, arith256_mod) of a native-verified Word16 bundle into in-circuit leaves; report gates and timings" },
    .{ .step = "rv64-recursion", .source = "src/integrations/riscv_cpu/rv64_recursion_main.zig", .description = "Build the RV64 recursion tools: wrap batch proofs into circuit leaves, fold them to one root, verify the root" },
};

pub fn addProduct(context: circuit_product.Context, product: graph.Product) void {
    for (roots) |spec| {
        const root = createRoot(context, product, spec.source);
        const executable = context.b.addExecutable(.{ .name = spec.step, .root_module = root });
        const install = context.b.addInstallArtifact(executable, .{});
        context.b.step(spec.step, spec.description).dependOn(&install.step);
    }
    const gkr_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_gkr_circuit_test_root.zig") });
    context.b.step("test-riscv64-gkr-circuit", "Qualify shared numerical GKR verifier on real circuit wires").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = gkr_tests, .minimum = 9 }}));
    const register_lane_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_register_boundary_lanes_test_root.zig") });
    context.b.step("test-riscv64-register-boundary-lanes", "Qualify dynamic register endpoints and scalar provider wires").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = register_lane_tests, .minimum = 7 }}));
    const ls_lane_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_ls_circuit_lanes_test_root.zig") });
    context.b.step("test-riscv64-ls-circuit-lanes", "Qualify dynamic LS boundary selection arithmetic wires").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = ls_lane_tests, .minimum = 6 }}));
    for ([_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "test-riscv64-recursion-circuit", .source = "src/integrations/riscv_cpu/rv64_recursion_circuit_test_root.zig" },
        .{ .name = "test-riscv64-shift-merged-circuit", .source = "src/integrations/riscv_cpu/rv64_shift_merged_circuit_test_root.zig" },
        .{ .name = "test-riscv64-alu-merged-circuit", .source = "src/integrations/riscv_cpu/rv64_alu_merged_circuit_test_root.zig" },
        .{ .name = "test-riscv64-multiplication-degree3-circuit", .source = "src/integrations/riscv_cpu/rv64_multiplication_degree3_circuit_test_root.zig" },
        .{ .name = "test-riscv64-keccak-pair2n-circuit", .source = "src/integrations/riscv_cpu/rv64_keccak_pair2n_circuit_test_root.zig" },
        .{ .name = "test-riscv64-division-degree3-circuit", .source = "src/integrations/riscv_cpu/rv64_division_degree3_circuit_test_root.zig" },
        .{ .name = "test-riscv64-division-product-circuit", .source = "src/integrations/riscv_cpu/rv64_division_product_circuit_test_root.zig" },
        .{ .name = "test-riscv64-word16-execution-circuit", .source = "src/integrations/riscv_cpu/rv64_word16_execution_circuit_test_root.zig" },
        .{ .name = "test-riscv64-v3-services-recursion", .source = "src/integrations/riscv_cpu/rv64_v3_services_recursion_test_root.zig" },
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
