//! Explicit host validation for the V3 retirement recipe. All architectural
//! semantics retain the canonical typed authority; only RAM predecessor gap
//! representation is delegated to the V3 original AIR and range16 provider.
const Authority = @import("../air/lang/typed_load_store_authority.zig");
const Clock = @import("../access_clock.zig");
const Chain = @import("state_chain.zig").StateChainTracker;
const Row = @import("trace_row.zig").TraceRow;
pub fn validateTraceRow(row: Row) !void {
    if (row.clk == 0 or row.clk > 1 << 24) return error.InvalidDirectRamClockRow;
    const current = Clock.encode(row.clk, .third);
    if (row.mem_prev_clk >= current or (row.mem_prev_clk != 0 and row.mem_prev_clk % 4 != 3)) return error.InvalidDirectRamClockRow;
    var canonical = row;
    canonical.mem_prev_clk = Chain.effectivePreviousClock(row.mem_prev_clk, current);
    try Authority.validateTraceRow(canonical);
}
