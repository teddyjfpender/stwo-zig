//! End-to-end RV32IM proof coverage for the fail-closed Metal engine.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const riscv_metal = @import("stwo_riscv_metal").integrations.riscv_metal;
const trace_mod = @import("stwo_riscv_metal").frontends.riscv.runner.trace;

const TEST_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

test "metal: RV32IM retirement trace proves and verifies without fallback" {
    const allocator = std.testing.allocator;
    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    trace.initial_pc = 0x1000;
    for (0..8) |index| {
        try trace.append(.{
            .clk = @intCast(index + 1),
            .pc = @intCast(0x1000 + index * 4),
            .opcode = .ADDI,
            .rd = 1,
            .rs1 = 0,
            .rs2 = 0,
            .imm = 1,
            .rs1_val = 0,
            .rs2_val = 0,
            .rs1_prev_clk = @intCast(index),
            .rd_prev_val = if (index == 0) 0 else 1,
            .rd_prev_clk = @intCast(index),
            .rd_val = 1,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1000 + (index + 1) * 4),
            .inst_word = 0x00100093,
        });
    }
    trace.final_pc = 0x1020;

    const output = try riscv_metal.proveRiscV(
        allocator,
        TEST_CONFIG,
        &trace,
        null,
        null,
    );
    defer output.deinitAfterProofMoved(allocator);
    try riscv_metal.verifyRiscV(
        allocator,
        TEST_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );
    try std.testing.expect(output.statement.n_components > 0);
}
