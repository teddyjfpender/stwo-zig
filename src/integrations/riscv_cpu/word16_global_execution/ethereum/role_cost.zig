//! Diagnostic native cells and padding from the actual admitted CPU roster.
//! Counts describe producer facts; they never replace physical bus closure.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = @import("../../word16_execution/geometry.zig");
const Prepared = @import("../../word16_execution/prepared.zig").Prepared;
const R = @import("../services/roster.zig");
const T = @import("../services/types.zig");
/// Core roles, one row per service family bridge, then the six v3
/// bulk-memory components (desc, copy, set, ucopy, cdesc, cmp) and the two v3 Keccak-sponge
/// components (call, perm).
pub const COUNT = G.ROLE_COUNT + T.FAMILIES + T.bulk_kinds.len + T.sponge_kinds.len + 1;
pub const Row = struct {
    role: []const u8,
    present: bool,
    log: u32,
    columns: [3]usize,
    native_rows: u64,
    active_rows: ?u64,
    padding_rows: ?u64,
    native_cells: [3]u64,
};
pub fn row(name: []const u8, log: u32, widths: [3]usize, active: ?u64) !Row {
    if (log > 30) return error.InvalidCostGeometry;
    const present = widths[0] != 0 or widths[1] != 0 or widths[2] != 0;
    const rows: u64 = if (present) G.rows(log) else 0;
    if (active) |n| if (n > rows) return error.InvalidActiveCostRows;
    var cells: [3]u64 = undefined;
    for (widths, &cells) |width, *out| out.* = try std.math.mul(u64, width, rows);
    return .{ .role = name, .present = present, .log = log, .columns = widths, .native_rows = rows, .active_rows = active, .padding_rows = if (active) |n| rows - n else null, .native_cells = cells };
}
pub fn build(setup: *const R.CpuSetup, prepared: *const Prepared, ram_events: u32, initial: usize, terminal: usize, calls: [T.FAMILIES]usize, bulk: T.BulkCounts, sponge: T.SpongeCounts) ![COUNT]Row {
    const g = setup.materials.geometry;
    const alu = try G.factCounts(prepared.alu.facts.len, g.alu_log, g.alu_tail_log);
    const binary = try G.factCounts(prepared.binary.facts.len, g.binary_log, g.binary_tail_log);
    const shift = try G.factCounts(prepared.shift.len, g.shift_log, g.shift_tail_log);
    const ls = try g.lsCounts(ram_events);
    var result: [COUNT]Row = undefined;
    for (setup.materials.shapes(), result[0..G.ROLE_COUNT]) |shape, *out| {
        const active: ?u64 = switch (shape.role) {
            .cpu => (prepared.cpu orelse return error.PreparedExecutionConsumed).public.steps,
            .alu => alu.head,
            .alu_tail => alu.tail,
            .binary => binary.head,
            .binary_tail => binary.tail,
            .shift => shift.head,
            .shift_tail => shift.tail,
            .ls => ls.head,
            .ls_tail => ls.tail,
            .initial => initial,
            .terminal => terminal,
            .jalr => prepared.raw_counts.jalr,
            .division => prepared.division.len,
            .multiplication => prepared.multiplication.len,
            // Fixed dictionaries and ROM occupancy are different from lookup
            // request counts. Do not invent active/padding counts for them.
            else => null,
        };
        out.* = try row(@tagName(shape.role), shape.log, shape.widths, active);
    }
    for (0..T.FAMILIES) |i| {
        const family: T.Family = @enumFromInt(i);
        // Active rows: 25 lanes per Keccak-f call, else the bridge's
        // coordinate rows per call (as plan.zig sizes them).
        const per_call: u64 = if (family == .keccak) 25 else A.crypto.secp256k1.word16_bridge.types.coordinates(T.bridgeKind(family));
        const log = setup.bridges.at(family);
        const active = try std.math.mul(u64, calls[i], per_call);
        result[G.ROLE_COUNT + i] = try row(bridgeName(family), log orelse 5, if (log != null) T.widths(family) else .{ 0, 0, 0 }, active);
    }
    for (T.bulk_kinds, 0..) |kind, k| {
        const log = setup.bridges.bulk.at(kind);
        result[G.ROLE_COUNT + T.FAMILIES + k] = try row(switch (kind) {
            inline else => |b| "bulk_" ++ @tagName(b),
        }, log orelse 5, if (log != null) T.bulkWidths(kind) else .{ 0, 0, 0 }, bulk.rows(kind));
    }
    for (T.sponge_kinds, 0..) |kind, k| {
        const log = setup.bridges.sponge.at(kind);
        result[G.ROLE_COUNT + T.FAMILIES + T.bulk_kinds.len + k] = try row(switch (kind) {
            .call => "sponge_call",
            .perm => "sponge_perm",
        }, log orelse 5, if (log != null) T.spongeWidths(kind) else .{ 0, 0, 0 }, sponge.rows(kind));
    }
    // Zbb BINARY component (v3_zbb): active rows = distinct Zbb facts.
    result[COUNT - 1] = try row("zbb_binary", setup.bridges.zbb orelse 5, if (setup.bridges.zbb != null) T.zbbWidths() else .{ 0, 0, 0 }, if (setup.bridges.zbb != null) prepared.zbb.facts.len else 0);
    for (0..3) |tree| {
        var width: usize = 0;
        for (result) |value| width = try std.math.add(usize, width, value.columns[tree]);
        if (width != setup.columnCount(tree)) return error.CostRosterMismatch;
    }
    return result;
}
fn bridgeName(family: T.Family) []const u8 {
    return switch (family) {
        inline else => |f| @tagName(f) ++ "_bridge",
    };
}
test "native cost rows distinguish absent roles unknown dictionary occupancy and padding" {
    const a = try row("facts", 10, .{ 2, 52, 32 }, 574);
    try std.testing.expectEqual(@as(?u64, 450), a.padding_rows);
    try std.testing.expectEqual([3]u64{ 2048, 53248, 32768 }, a.native_cells);
    const empty = try row("absent", 5, .{ 0, 0, 0 }, 0);
    try std.testing.expect(!empty.present);
    try std.testing.expectEqual(@as(u64, 0), empty.native_rows);
    const dictionary = try row("fixed_table", 16, .{ 3, 1, 8 }, null);
    try std.testing.expectEqual(@as(?u64, null), dictionary.padding_rows);
    try std.testing.expectError(error.InvalidActiveCostRows, row("bad", 5, .{ 0, 0, 0 }, 1));
}
