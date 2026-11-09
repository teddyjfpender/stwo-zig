//! Committed main columns for Stark-V's ordinary RW-memory boundary table.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const canonical_infra_e77bab = @import("stwo_riscv_air_lang").shared_infra_trace_permutation;
const boundary = @import("boundary.zig");

pub const N_COLUMNS: usize = 8;

pub const Columns = struct {
    values: [N_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        for (&self.values) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    rows: []const boundary.Row,
    log_size: u32,
) !Columns {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    var result: Columns = undefined;
    var initialized: usize = 0;
    errdefer for (result.values[0..initialized]) |column| allocator.free(column);
    for (&result.values) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    const table = try canonical_infra_e77bab.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (rows, 0..) |row, index| {
        const dst = table.map(index);
        result.values[0][dst] = M31.fromU64(row.addr);
        result.values[1][dst] = M31.fromU64(row.clock);
        for (row.value, 0..) |value, limb| result.values[2 + limb][dst] = M31.fromU64(value);
        result.values[6][dst] = row.multiplicity;
        result.values[7][dst] = M31.fromU64(row.root);
    }
    return result;
}

test "memory boundary trace commits exact rows and zero padding" {
    const rows = [_]boundary.Row{.{
        .addr = 0x1000,
        .clock = 7,
        .value = .{ 1, 2, 3, 4 },
        .multiplicity = M31.one().neg(),
        .root = 99,
    }};
    var columns = try generate(std.testing.allocator, &rows, 2);
    defer columns.deinit(std.testing.allocator);
    const table = try canonical_infra_e77bab.BitReversalTable.init(std.testing.allocator, 2);
    defer table.deinit(std.testing.allocator);
    const row = table.map(0);
    try std.testing.expectEqual(@as(u32, 0x1000), columns.values[0][row].toU32());
    try std.testing.expectEqual(@as(u32, 99), columns.values[7][row].toU32());
    try std.testing.expect(columns.values[6][row].eql(M31.one().neg()));
    try std.testing.expect(columns.values[6][table.map(1)].isZero());
}
