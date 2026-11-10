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
    .{ .step = "rv64-op-group-root", .source = "src/integrations/riscv_cpu/rv64_op_group_root_main.zig", .description = "Experimental direct native-group OP root producer and independent source-only receiver" },
    .{ .step = "rv64-op-root", .source = "src/integrations/riscv_cpu/rv64_op_root_main.zig", .description = "Explicit OP R5 physical-root producer and source-owned root-only receiver" },
    .{ .step = "rv64-word16-ethereum-gkr", .source = "src/integrations/riscv_cpu/rv64_word16_ethereum_gkr_main.zig", .description = "Prove or inspect native OM31 Ethereum/OP guest execution with explicit recursion dependencies" },
    .{ .step = "rv64-poseidon-graph-fixture", .source = "src/integrations/riscv_cpu/rv64_poseidon_graph_fixture_main.zig", .description = "Real source-owned five-roster P2 v2 graph STARK and fresh receiver" },
    .{ .step = "rv64-poseidon-row-fixture", .source = "src/integrations/riscv_cpu/rv64_poseidon_row_fixture_main.zig", .description = "Scoped dedicated Poseidon row STARK and fresh receiver" },
    .{ .step = "rv64-word16-ethereum-gkr-recursion", .source = "src/integrations/riscv_cpu/rv64_om31_recursion_main.zig", .description = "Wrap current OM31 Ethereum CPU/truth proofs, fold and freshly verify their execution root" },
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
        if (std.mem.eql(u8, spec.step, "rv64-op-group-root")) {
            const check = context.b.addExecutable(.{ .name = "rv64-op-group-root-check", .root_module = root });
            context.b.step("check-rv64-op-group-root", "Type-check explicit grouped OP root without LLVM output").dependOn(&check.step);
        }
        if (std.mem.eql(u8, spec.step, "rv64-op-root")) {
            const check = context.b.addExecutable(.{ .name = "rv64-op-root-check", .root_module = root });
            context.b.step("check-rv64-op-root", "Type-check the explicit OP root CLI without LLVM output").dependOn(&check.step);
        }
        if (std.mem.eql(u8, spec.step, "rv64-word16-ethereum-gkr-recursion")) {
            const check = context.b.addExecutable(.{ .name = "rv64-word16-recursion-check", .root_module = root });
            context.b.step("check-rv64-ethereum-recursion", "Type-check the current OM31 execution recursion route without LLVM output").dependOn(&check.step);
        }
    }
    const gkr_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_gkr_circuit_test_root.zig") });
    context.b.step("test-riscv64-gkr-circuit", "Qualify shared numerical GKR verifier on real circuit wires").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = gkr_tests, .minimum = 9 }}));
    // M4 diet stream (measurement-only prototype).
    const diet_gkr_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_outer_gkr_diet_test_root.zig"), .filters = &.{"outer LogUp-GKR"} });
    context.b.step("test-riscv64-outer-gkr-diet", "Measure the outer LogUp-GKR in-circuit verifier cost (M7 diet prototype)").dependOn(&context.b.addRunArtifact(diet_gkr_tests).step);
    // M5 stream outer-gkr (profile outer_gkr_om31_strict_v1; off by default, new files only).
    const outer_gkr_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_outer_gkr_test_root.zig"), .filters = &.{"outer GKR"} });
    context.b.step("test-riscv64-outer-gkr", "Qualify the outer LogUp-GKR section: CPU reference, tamper corpus, in-circuit gadget").dependOn(&context.b.addRunArtifact(outer_gkr_tests).step);
    const outer_gkr_tool = context.b.addExecutable(.{ .name = "rv64-outer-gkr-tool", .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_outer_gkr_tool_main.zig") });
    context.b.step("rv64-outer-gkr-tool", "Outer LogUp-GKR producer/receiver/cost tool (fresh-process receiver for the tamper corpus)").dependOn(&context.b.addInstallArtifact(outer_gkr_tool, .{}).step);
    const register_lane_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_register_boundary_lanes_test_root.zig") });
    context.b.step("test-riscv64-register-boundary-lanes", "Qualify dynamic register endpoints and scalar provider wires").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = register_lane_tests, .minimum = 7 }}));
    const ls_lane_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_ls_circuit_lanes_test_root.zig") });
    context.b.step("test-riscv64-ls-circuit-lanes", "Qualify dynamic LS boundary selection arithmetic wires").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = ls_lane_tests, .minimum = 6 }}));
    // Focused terminal-only loop: no unrelated dense/pairing fixture roots.
    const terminal_source = "src/integrations/riscv_cpu/rv64_op_terminal_blake_test_root.zig";
    const terminal_filters = test_filter.apply(context.b, &.{ "terminal Blake", "terminal fresh path" });
    const terminal_check = context.b.addTest(.{ .root_module = createRoot(context, product, terminal_source), .filters = terminal_filters });
    context.b.step("check-riscv64-op-terminal-blake", "Type-check isolated R6/R7 terminal Blake gates without LLVM output").dependOn(&terminal_check.step);
    const terminal_tests = context.b.addTest(.{ .root_module = createRoot(context, product, terminal_source), .filters = terminal_filters });
    context.b.step("test-riscv64-op-terminal-blake", "Qualify isolated terminal Blake formats, env-gated actual roots and fresh-path policy").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = terminal_tests, .minimum = 6 }}));
    const op_pure_p2_check = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_op_pure_p2_test_root.zig"), .filters = test_filter.apply(context.b, &.{"OP pure P2"}) });
    context.b.step("check-riscv64-op-pure-p2", "Type-check OP P2 reference gates without emitting or running test binaries").dependOn(&op_pure_p2_check.step);
    const op_group_check = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_op_pure_p2_test_root.zig"), .filters = test_filter.apply(context.b, &.{"direct native group"}) });
    context.b.step("check-riscv64-op-native-group", "Type-check closed direct-native group source without LLVM output").dependOn(&op_group_check.step);
    const op_group_tests = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_op_pure_p2_test_root.zig"), .filters = test_filter.apply(context.b, &.{"direct native group"}) });
    context.b.step("test-riscv64-op-native-group", "Qualify direct native group source, padding census and standalone parity without an outer proof").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = op_group_tests, .minimum = 2 }}));
    const op_truth_p2 = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_op_pure_p2_test_root.zig"), .filters = test_filter.apply(context.b, &.{"OP pure P2 complete catalog"}) });
    context.b.step("test-riscv64-op-truth-recursion", "Qualify complete native P2 truth catalog recursive statements and representative physical leaves").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = op_truth_p2, .minimum = 6 }}));
    const op_tower_p2 = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_op_pure_p2_test_root.zig"), .filters = test_filter.apply(context.b, &.{"OP pure P2 complete Miller truth circuit"}) });
    context.b.step("test-riscv64-op-tower-recursion", "Qualify complete OP Miller truth recursive statement and physical leaf").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = op_tower_p2, .minimum = 1 }}));
    const op_pure_p2 = context.b.addTest(.{ .root_module = createRoot(context, product, "src/integrations/riscv_cpu/rv64_op_pure_p2_test_root.zig"), .filters = test_filter.apply(context.b, &.{"OP pure P2"}) });
    context.b.step("test-riscv64-op-pure-p2", "Qualify new OP pure-P2 numerical and physical gates without production admission").dependOn(test_filter.addSuites(context.b, &.{.{ .tests = op_pure_p2, .minimum = 4 }}));
    for ([_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "test-riscv64-poseidon-matched-blake-census", .source = "src/integrations/riscv_cpu/rv64_poseidon_matched_blake_census_test_root.zig" },
        .{ .name = "test-riscv64-poseidon-pure-leaf-census", .source = "src/integrations/riscv_cpu/rv64_poseidon_pure_cpu_census_test_root.zig" },
        .{ .name = "test-riscv64-poseidon-full-leaf-census", .source = "src/integrations/riscv_cpu/rv64_poseidon_full_cpu_census_test_root.zig" },
        .{ .name = "test-riscv64-poseidon2-gadgets", .source = "src/integrations/riscv_cpu/rv64_poseidon2_gadgets_test_root.zig" },
        .{ .name = "test-riscv64-poseidon2-circuit", .source = "src/integrations/riscv_cpu/rv64_poseidon2_circuit_test_root.zig" },
        .{ .name = "test-riscv64-om31-outer", .source = "src/integrations/riscv_cpu/rv64_om31_outer_test_root.zig" },
        .{ .name = "test-riscv64-outer-gkr-cpu-polynomial", .source = "src/integrations/riscv_cpu/rv64_outer_gkr_cpu_polynomial_test_root.zig" },
        .{ .name = "test-riscv64-outer-gkr-cpu-lowering", .source = "src/integrations/riscv_cpu/rv64_outer_gkr_cpu_lowering_test_root.zig" },
        .{ .name = "test-riscv64-outer-gkr-cpu-native", .source = "src/integrations/riscv_cpu/rv64_outer_gkr_cpu_native_test_root.zig" },
        .{ .name = "test-riscv64-om31-m3-fold", .source = "src/integrations/riscv_cpu/rv64_om31_m3_fold_test_root.zig" },
        .{ .name = "test-riscv64-op-public-fold", .source = "src/integrations/riscv_cpu/rv64_op_public_fold_test_root.zig" },
        .{ .name = "test-riscv64-m5-vk-table", .source = "src/integrations/riscv_cpu/rv64_m5_vk_table_test_root.zig" },
        .{ .name = "test-riscv64-m5-rootverify", .source = "src/integrations/riscv_cpu/rv64_m5_rootverify_test_root.zig" },
        .{ .name = "test-riscv64-structural-arithmetic", .source = "src/integrations/riscv_cpu/rv64_structural_arithmetic_test_root.zig" },
        .{ .name = "test-riscv64-native-group", .source = "src/integrations/riscv_cpu/rv64_native_group_test_root.zig" },
        .{ .name = "test-riscv64-om31-native-pcs", .source = "src/integrations/riscv_cpu/rv64_om31_native_pcs_test_root.zig" },
        .{ .name = "test-riscv64-om31-services-root", .source = "src/integrations/riscv_cpu/rv64_om31_services_root_test_root.zig" },
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
        const tests = context.b.addTest(.{ .root_module = createRoot(context, product, spec.source), .filters = if (std.mem.eql(u8, spec.name, "test-riscv64-structural-arithmetic")) &.{"structural circuit arithmetic"} else if (std.mem.eql(u8, spec.name, "test-riscv64-native-group")) &.{"native verifier group"} else if (std.mem.eql(u8, spec.name, "test-riscv64-om31-native-pcs")) &.{ "OM31 native PCS", "OM31 frame", "OM31 V3" } else if (std.mem.eql(u8, spec.name, "test-riscv64-poseidon-full-leaf-census")) &.{"actual complete CPU P2 mixed recursive leaf"} else if (std.mem.eql(u8, spec.name, "test-riscv64-poseidon-pure-leaf-census")) &.{"source-exact complete CPU pure P2 candidate"} else if (std.mem.eql(u8, spec.name, "test-riscv64-poseidon-matched-blake-census")) &.{"matched all-Blake complete CPU b4 q54 P20"} else &.{} });
        const run = context.b.addRunArtifact(tests);
        run.setCwd(context.b.path("."));
        context.b.step(spec.name, "Qualify native and circuit-lane execution authorities").dependOn(&run.step);
    }
}

fn createRoot(context: circuit_product.Context, product: graph.Product, source: []const u8) *std.Build.Module {
    const root = createRootBase(context, product, source);
    // Pure arithmetic checks deliberately avoid a native compiler dependency.
    if (!std.mem.endsWith(u8, source, "rv64_op_terminal_blake_test_root.zig") and !std.mem.endsWith(u8, source, "rv64_op_pure_p2_test_root.zig") and !std.mem.endsWith(u8, source, "rv64_structural_arithmetic_test_root.zig") and !std.mem.endsWith(u8, source, "rv64_outer_gkr_cpu_lowering_test_root.zig") and !std.mem.endsWith(u8, source, "rv64_outer_gkr_cpu_polynomial_test_root.zig")) root.addImport("outer_gkr_cpu_aot", createHybridModule(context, product, root.import_table.get("stwo_cairo_frontend").?));
    return root;
}

/// The generator uses this source stack without importing its own generated
/// module. It depends on the original circuit kernels only, so there is no
/// generated-kernel/bootstrap cycle.
fn createRootBase(context: circuit_product.Context, product: graph.Product, source: []const u8) *std.Build.Module {
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

fn createHybridModule(context: circuit_product.Context, product: graph.Product, cairo: *std.Build.Module) *std.Build.Module {
    const b = context.b;
    var host = context;
    host.target = b.graph.host;
    host.optimize = .ReleaseFast;
    const generator_root = createRootBase(host, product, "src/integrations/riscv_cpu/rv64_outer_gkr_cpu_codegen_main.zig");
    generator_root.addImport("hybrid_cpu_emitter", b.createModule(.{ .root_source_file = b.path("src/tools/cairo_composition_cpu_codegen/hybrid_om31_writer.zig"), .target = b.graph.host, .optimize = .ReleaseFast }));
    const generator = b.addExecutable(.{ .name = "rv64-hybrid-cpu-codegen", .root_module = generator_root });
    const generate = b.addRunArtifact(generator);
    generate.addFileArg(b.path("vectors/circuit/official/circuit_air.air_programs_v1.bin"));
    const directory = generate.addOutputDirectoryArg("rv64-hybrid-cpu-aot");
    const module = b.createModule(.{ .root_source_file = directory.path(b, "registry.zig"), .target = context.target, .optimize = context.optimize });
    module.addImport("stwo_cairo_frontend", cairo);
    const library = b.addLibrary(.{ .name = "rv64-hybrid-cpu-polynomial-kernels", .linkage = .static, .root_module = b.createModule(.{ .target = context.target, .optimize = context.optimize, .pic = true, .link_libc = true }) });
    for (0..11) |index| library.root_module.addCSourceFile(.{ .file = directory.path(b, b.fmt("hybrid_{d}.c", .{index})), .flags = &.{ "-std=c11", "-O3", "-fstrict-aliasing", "-fno-vectorize", "-fno-slp-vectorize", "-gline-tables-only" } });
    module.linkLibrary(library);
    return module;
}

comptime {
    _ = riscv_cpu_tests;
    _ = test_filter;
}
