//! Shared checked LS arithmetic, separate RAM and merged local lookup debt.
const V1 = @import("../load_store_v1/layout.zig");
const R = @import("../closed_ram/layout.zig");
pub const Kind = enum { ls, initial, terminal, range16, range8, selection };
pub const projection = @import("projection.zig");
pub const MAIN = projection.MAIN;
pub const LOCAL_INVERSES = 8;
pub const LOCAL_PREFIX = LOCAL_INVERSES + 4 * LOCAL_PAIRS;
pub const INTERACTION = LOCAL_PREFIX + 4;
// INIT/TEARDOWN keep only the canonical RAM14 tuple prefix of the closed
// boundary row (active, address4, value4, epoch, tick lo/hi, R, W). Sorted,
// unique, aligned addresses are NOT re-proved in-chip: every accepting
// receiver validates them natively on the public cell list and compares the
// chip's RAM debt exactly against expectedClaim (see
// design/riscv-proving-stack/rv64-boundary-public-sortedness-v1.md).
pub const BOUND_MAIN = 14;
pub const BOUND_INTERACTION = 8;
// A/I/B come from the closed CPU REG/ROM/OWNER relations. RAM before
// coordinates inherit canonical produced states; addresses additionally use
// strict RAM chronology and canonical aligned INIT coverage. Keep independent
// write anchors (after-value and load C), clock limbs, all gaps and byte splits.
pub const LOGICAL_U16 = [_]usize{ 12, 18, 19, 20, 21, 24, 25, 40, 41, 42, 43, 68 };
pub const LOGICAL_U8 = [_]usize{ 13, 26, 73, 74 };
pub const U16 = projection.columns(&LOGICAL_U16);
/// U8 queries include the retired affine b_low (logical 73), so they have no
/// physical-column map; evaluate them on projection.expandFor rows.
pub const U8_QUERIES = LOGICAL_U8.len;
pub const LOCAL_FRACTIONS = 2 + U16.len + U8_QUERIES;
pub const LOCAL_PAIRS = (LOCAL_FRACTIONS + 1) / 2;
// Narrow native caches still retain every RAM/OWNER coordinate. Removing a
// lookup must never remove the metadata needed after MAIN ownership transfer.
pub const RELATION_U16 = V1.U16;
pub const RELATION_U8 = V1.U8;
pub const U16_CACHE = cacheIndices(&LOGICAL_U16, &RELATION_U16);
pub const U8_CACHE = cacheIndices(&LOGICAL_U8, &RELATION_U8);
fn cacheIndices(comptime queries: []const usize, comptime cached: []const usize) [queries.len]usize {
    var result: [queries.len]usize = undefined;
    for (queries, 0..) |column, at| {
        result[at] = for (cached, 0..) |c, i| {
            if (c == column) break i;
        } else @compileError("missing retained LS relation coordinate");
    }
    return result;
}
pub fn widths(kind: Kind) [3]usize {
    return switch (kind) {
        .ls => .{ 3, MAIN, INTERACTION },
        .selection => V1.widths(.selection),
        .initial, .terminal => .{ 3, BOUND_MAIN, BOUND_INTERACTION },
        .range16 => R.widths(.range16),
        .range8 => R.widths(.range8),
    };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .ls => 261,
        .initial, .terminal => 25,
        .selection => 3,
        .range16, .range8 => 3,
    };
}
pub fn previousMainFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .ls => V1.previousMainFor(.ls, c),
        .initial, .terminal => c == 0,
        else => false,
    };
}
pub fn previousInterFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .ls => (c >= 4 and c < 8) or c >= LOCAL_PREFIX,
        .initial, .terminal => c >= 4 and c < 8,
        else => c >= 4,
    };
}
