//! Private V3 auxiliaries. Originals and HALT columns are borrowed, never copied.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const K = @import("block_v8_ram_clock_v3_kernel.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
pub const Owned = struct {
    a: std.mem.Allocator,
    original_count: usize,
    columns: []Column,
    pub fn deinit(self: *Owned) void {
        for (self.columns[self.original_count..]) |column| self.a.free(column.values);
        self.a.free(self.columns);
        self.* = undefined;
    }
};
pub fn mainLogs(a: std.mem.Allocator, shape: *const Shape) ![]u32 {
    const base = try Halt.mainLogs(a, shape);
    defer a.free(base);
    const logs = try a.alloc(u32, base.len + 3 * Halt.count(shape));
    @memcpy(logs[0..base.len], base);
    var offset = base.len;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        @memset(logs[offset..][0..3], desc.log_size);
        offset += 3;
    };
    return logs;
}
pub fn prepare(a: std.mem.Allocator, shape: *const Shape, guarded: []const Column) !Owned {
    const expected = try Halt.mainLogs(a, shape);
    defer a.free(expected);
    if (expected.len != guarded.len) return error.InvalidDirectRamClockColumns;
    for (guarded, expected) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidDirectRamClockColumns;
    const policy = try K.Policy.fromCycles(shape.public_data.clock);
    const columns = try a.alloc(Column, guarded.len + 3 * Halt.count(shape));
    errdefer a.free(columns);
    @memcpy(columns[0..guarded.len], guarded);
    var ready = guarded.len;
    errdefer for (columns[guarded.len..ready]) |column| a.free(column.values);
    var offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        defer offset += desc.n_columns;
        if (desc.family != .load_store) continue;
        if (desc.n_columns != 50) return error.UnsupportedDirectRamClockProfile;
        const size = @as(usize, 1) << @intCast(desc.log_size);
        for (0..3) |_| {
            columns[ready] = .{ .log_size = desc.log_size, .values = try a.alloc(M, size) };
            ready += 1;
        }
        for (0..size) |physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, desc.log_size), desc.log_size);
            const active = logical < desc.n_rows;
            const store = guarded[offset + 39].values[physical].add(guarded[offset + 40].values[physical]).add(guarded[offset + 41].values[physical]);
            const source = guarded[offset + 23].values[physical];
            const destination = guarded[offset + 7].values[physical];
            if (active and store.v > 1) return error.InvalidDirectRamClockColumns;
            const previous = source.add(store.mul(destination.sub(source)));
            const clock = guarded[offset].values[physical];
            const current = if (active) try std.math.sub(u32, try std.math.mul(u32, clock.v, 4), 1) else 0;
            const row = try K.witness(policy, active, current, previous.v);
            for (row, 0..) |value, i| @constCast(columns[ready - 3 + i].values)[physical] = value;
        }
    }
    return .{ .a = a, .original_count = guarded.len, .columns = columns };
}
