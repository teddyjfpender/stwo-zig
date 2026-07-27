//! Fast RISC-V runner, witness, and AIR unit coverage.

const std = @import("std");

pub const runner = @import("../../frontends/riscv/runner/mod.zig");
const infra_trace = @import("../../frontends/riscv/infra_trace.zig");
const StateChainTracker = @import("../../frontends/riscv/runner/state_chain.zig").StateChainTracker;

test {
    std.testing.refAllDeclsRecursive(runner);
    _ = @import("../../frontends/riscv/air/clock_update_component_test.zig");
    _ = @import("../../frontends/riscv/air/component_order.zig");
    _ = @import("../../frontends/riscv/air/extract/mod.zig");
    _ = @import("../../frontends/riscv/air/logup.zig");
    _ = @import("../../frontends/riscv/air/interaction.zig");
    _ = @import("../../frontends/riscv/air/memory_commitment/mod.zig");
    _ = @import("../../frontends/riscv/air/program/mod.zig");
    _ = @import("../../frontends/riscv/air/relation_export.zig");
    _ = @import("../../frontends/riscv/air/relation_export_components.zig");
    _ = @import("../../frontends/riscv/air/relation_export_components_test.zig");
    _ = @import("../../frontends/riscv/air/relation_export_test.zig");
    _ = @import("../../frontends/riscv/air/relation_evidence.zig");
    _ = @import("../../frontends/riscv/air/relations.zig");
    _ = @import("../../frontends/riscv/air/semantic_component_test.zig");
    _ = @import("../../frontends/riscv/air/semantics/mod.zig");
    _ = @import("../../frontends/riscv/air/transcript/mod.zig");
    _ = @import("../../frontends/riscv/diagnostics/public_values.zig");
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
