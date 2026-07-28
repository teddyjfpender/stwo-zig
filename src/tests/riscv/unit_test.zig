//! Fast RISC-V runner, witness, and AIR unit coverage.

const std = @import("std");

pub const runner = @import("stwo_riscv_frontend").runner;
const infra_trace = @import("stwo_riscv_frontend").infra_trace;
const StateChainTracker = @import("stwo_riscv_frontend").runner.state_chain.StateChainTracker;

test {
    std.testing.refAllDeclsRecursive(runner);
    _ = @import("stwo_riscv_frontend").testing.clock_update_component_test;
    _ = @import("stwo_riscv_frontend").air.component_order;
    _ = @import("stwo_riscv_frontend").air.extract;
    _ = @import("stwo_riscv_frontend").air.logup;
    _ = @import("stwo_riscv_frontend").air.interaction;
    _ = @import("stwo_riscv_frontend").air.memory_commitment;
    _ = @import("stwo_riscv_frontend").air.program;
    _ = @import("stwo_riscv_frontend").air.relation_export;
    _ = @import("stwo_riscv_frontend").air.relation_export_components;
    _ = @import("stwo_riscv_frontend").testing.relation_export_components_test;
    _ = @import("stwo_riscv_frontend").testing.relation_export_test;
    _ = @import("stwo_riscv_frontend").air.relation_evidence;
    _ = @import("stwo_riscv_frontend").air.relations;
    _ = @import("stwo_riscv_frontend").testing.semantic_component_test;
    _ = @import("stwo_riscv_frontend").air.semantics;
    _ = @import("stwo_riscv_frontend").air.transcript;
    _ = @import("stwo_riscv_frontend").diagnostics.public_values;
}

test "infra_trace: genMemoryColumns caps rows at the domain size" {
    const allocator = std.testing.allocator;
    var chain = StateChainTracker.init(allocator);
    defer chain.deinit();
    try chain.recordRegAccess(1, 0, 42);
    try chain.recordRegAccess(2, 2, 100);
    try chain.recordMemAccess(0x1000, 4, 0xDEADBEEF);
    try chain.recordMemAccess(0x2000, 6, 0xCAFEBABE);
    try chain.recordMemAccess(0x1000, 8, 0x12345678);

    const log_size: u32 = 2;
    var result = try infra_trace.genMemoryColumns(allocator, &chain, log_size);
    defer infra_trace.freeMemoryColumns(allocator, &result.columns);
    try std.testing.expectEqual(@as(usize, 4), result.n_real_rows);
}
