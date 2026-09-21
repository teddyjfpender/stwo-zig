//! Capacity admission for a bounded resumable execution leaf.
//!
//! The segment budget is known before the first retirement. Reserving the
//! dense trace and ordinary-access log once avoids repeatedly copying their
//! multi-million-entry prefixes as `ArrayList` grows. This is allocation-only
//! admission: no architectural, trace, or state-chain record is published.

const std = @import("std");
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

/// Every migrated ordinary RV32IM family records at most two source accesses
/// and one destination/memory access. Profile-extension transactions reserve
/// their larger batches independently and can consume unused capacity here.
pub const MAX_ORDINARY_ACCESSES_PER_RETIREMENT: usize = 3;

pub fn reserveLeafLogs(
    execution_trace: *Trace,
    chain_tracker: *StateChainTracker,
    step_budget: usize,
) !void {
    const access_budget = std.math.mul(
        usize,
        step_budget,
        MAX_ORDINARY_ACCESSES_PER_RETIREMENT,
    ) catch return error.LeafCapacityOverflow;

    try execution_trace.reserveAdditional(step_budget);
    try chain_tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = access_budget,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    });
}

test "bounded leaf capacity is admitted before publication" {
    var execution_trace = Trace.init(std.testing.allocator);
    defer execution_trace.deinit();
    var chain_tracker = StateChainTracker.init(std.testing.allocator);
    defer chain_tracker.deinit();

    try reserveLeafLogs(&execution_trace, &chain_tracker, 8);
    try std.testing.expect(execution_trace.rows.capacity >= 8);
    try std.testing.expect(chain_tracker.accesses.capacity >= 24);
    try std.testing.expectEqual(@as(usize, 0), execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 0), chain_tracker.accesses.items.len);
}

test "bounded leaf capacity rejects arithmetic overflow before allocation" {
    var execution_trace = Trace.init(std.testing.allocator);
    defer execution_trace.deinit();
    var chain_tracker = StateChainTracker.init(std.testing.allocator);
    defer chain_tracker.deinit();

    try std.testing.expectError(
        error.LeafCapacityOverflow,
        reserveLeafLogs(&execution_trace, &chain_tracker, std.math.maxInt(usize)),
    );
    try std.testing.expectEqual(@as(usize, 0), execution_trace.rows.capacity);
    try std.testing.expectEqual(@as(usize, 0), chain_tracker.accesses.capacity);
}
