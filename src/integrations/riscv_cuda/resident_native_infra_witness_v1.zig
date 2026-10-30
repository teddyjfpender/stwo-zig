//! Original clock/frame row writers, mechanically lowered to CUDA. Raw clock
//! updates are execution-log operands, never precomputed proof columns.
const std = @import("std");
const Core = @import("stwo_core");
const Clock = @import("../../frontends/riscv/infra_trace/clock_update.zig");
const Chain = @import("../../frontends/riscv/runner/state_chain.zig");
const Frame = @import("../../frontends/riscv/prover/block_v5_native_frame_v1.zig");
pub const CLOCK_RAW_WORDS = 5;
pub fn clock(raw: *const [5]u32) ![10]u32 {
    if (raw[0] > 1 or raw[3] >= Chain.CLOCK_PREV_BOUND or raw[2] != raw[3] + Chain.MAX_CLOCK_DIFF) return error.InvalidNativeClockRecord;
    const update = Chain.ClockUpdate{ .addr_space = @intCast(raw[0]), .addr = raw[1], .clk = raw[2], .clk_prev = raw[3], .value = raw[4] };
    var result: [10]u32 = undefined;
    for (Clock.rowValues(raw[0], update), &result) |value, *out| out.* = value.v;
    return result;
}
fn committed(index: usize, rows: usize) usize {
    const log: @TypeOf(@as(u5, 0)) = @intCast(@ctz(rows));
    return Core.utils.bitReverseIndex(Core.utils.cosetIndexToCircleDomainIndex(index, log), log);
}
fn clockRow(raw: [*]const u32, out: [*]u32, count: u32, rows: u32, index: u32) callconv(.c) u32 {
    if (rows < 2 or rows > (1 << 24) or rows & (rows - 1) != 0 or count > rows or index >= rows) return 1;
    var values: [10]u32 = @splat(0);
    if (index < count) {
        var input: [5]u32 = undefined;
        @memcpy(&input, raw[5 * @as(usize, index) ..][0..5]);
        if (index > 0 and raw[5 * (@as(usize, index) - 1)] > input[0]) return 2;
        values = clock(&input) catch return 2;
    }
    const dst = committed(index, rows);
    for (values, 0..) |value, c| out[c * rows + dst] = value;
    return 0;
}
fn frameRow(out: [*]u32, rows: u32, index: u32, steps: u32, external: u32) callconv(.c) u32 {
    if (rows != (1 << Frame.LOG_SIZE) or index >= rows or steps == 0 or steps != external or steps >= Core.fields.m31.Modulus) return 1;
    const values = [_]u32{ Frame.TAG, Frame.VERSION, steps, external };
    for (values, 0..) |value, c| out[c * rows + index] = value;
    return 0;
}
fn fixedRow(first: [*]u32, active: [*]u32, rows: u32, count: u32, index: u32, frame: u32) callconv(.c) u32 {
    if (rows < 2 or rows > (1 << 24) or rows & (rows - 1) != 0 or count > rows or index >= rows or frame > 1) return 1;
    if (frame == 1) {
        if (rows != 4 or count != 4) return 1;
        first[index] = 1;
        return 0;
    }
    const dst = committed(index, rows);
    first[dst] = @intFromBool(index == 0);
    active[dst] = @intFromBool(index < count);
    return 0;
}
pub fn exportWriters() void {
    comptime {
        @export(&clockRow, .{ .name = "stwo_native_infra_clock_v1" });
        @export(&fixedRow, .{ .name = "stwo_native_infra_fixed_v1" });
        @export(&frameRow, .{ .name = "stwo_native_infra_frame_v1" });
    }
}
test "resident native infra exact original clock columns and committed padding" {
    const a = std.testing.allocator;
    var chain = Chain.StateChainTracker.init(a);
    defer chain.deinit();
    try chain.recordRegAccess(2, 0, 0x12345678);
    try chain.recordRegAccess(2, 2 * Chain.MAX_CLOCK_DIFF + 7, 0x12345678);
    try chain.recordMemAccess(0x80002000, 0, 0xfedcba98);
    try chain.recordMemAccess(0x80002000, 3 * Chain.MAX_CLOCK_DIFF + 9, 0xfedcba98);
    var original = try Clock.genClockUpdateColumns(a, &chain, 3);
    defer Clock.freeClockUpdateColumns(a, &original.columns);
    var raw: [5 * 8]u32 = @splat(0);
    var count: usize = 0;
    inline for (.{ chain.clock_updates_reg.items, chain.clock_updates_mem.items }) |updates| for (updates) |update| {
        @memcpy(raw[count * 5 ..][0..5], &[_]u32{ @as(u32, update.addr_space), update.addr, update.clk, update.clk_prev, update.value });
        count += 1;
    };
    var result: [10 * 8]u32 = @splat(0xdeadbeef);
    for (0..8) |i| try std.testing.expectEqual(@as(u32, 0), clockRow(&raw, &result, @intCast(count), 8, @intCast(i)));
    for (original.columns, 0..) |column, c| for (column, 0..) |value, r| try std.testing.expectEqual(value.v, result[c * 8 + r]);
    var bad = [_]u32{ 0, 2, 0, Chain.CLOCK_PREV_BOUND, 0 };
    try std.testing.expectError(error.InvalidNativeClockRecord, clock(&bad));
    bad = .{ 2, 2, Chain.MAX_CLOCK_DIFF, 0, 0 };
    try std.testing.expectError(error.InvalidNativeClockRecord, clock(&bad));
    bad = .{ 0, 2, Chain.MAX_CLOCK_DIFF - 1, 0, 0 };
    try std.testing.expectError(error.InvalidNativeClockRecord, clock(&bad));
    var untouched: [80]u32 = @splat(123);
    try std.testing.expectEqual(@as(u32, 2), clockRow(&bad, &untouched, 1, 8, 0));
    for (untouched) |x| try std.testing.expectEqual(@as(u32, 123), x);
}
test "resident native physical frame exact original geometry and rejects fabricated counts" {
    var out: [16]u32 = @splat(0);
    for (0..4) |i| try std.testing.expectEqual(@as(u32, 0), frameRow(&out, 4, @intCast(i), 9, 9));
    for ([_]u32{ Frame.TAG, Frame.VERSION, 9, 9 }, 0..) |value, c| for (out[c * 4 ..][0..4]) |x| try std.testing.expectEqual(value, x);
    try std.testing.expectEqual(@as(u32, 1), frameRow(&out, 4, 0, 9, 8));
}

test "resident native fixed selectors match original preprocessed columns" {
    const Opcode = @import("../../frontends/riscv/prover/opcode_trace.zig");
    const a = std.testing.allocator;
    for ([_]u32{ 1, 2, 3, 7 }) |log| {
        const rows = @as(u32, 1) << @intCast(log);
        const f = try a.alloc(u32, rows);
        defer a.free(f);
        const v = try a.alloc(u32, rows);
        defer a.free(v);
        for ([_]u32{ 0, 1, rows - 1, rows }) |count| {
            const first = try Opcode.generateIsFirst(a, log);
            defer a.free(first);
            const active = try Opcode.generateIsActive(a, log, count);
            defer a.free(active);
            for (0..rows) |i| try std.testing.expectEqual(@as(u32, 0), fixedRow(f.ptr, v.ptr, rows, count, @intCast(i), 0));
            for (first, active, f, v) |x, y, fx, fy| {
                try std.testing.expectEqual(x.v, fx);
                try std.testing.expectEqual(y.v, fy);
            }
        }
    }
    var frame: [4]u32 = @splat(0);
    for (0..4) |i| try std.testing.expectEqual(@as(u32, 0), fixedRow(&frame, &frame, 4, 4, @intCast(i), 1));
    const original = try Frame.fixedColumns(a);
    defer Frame.freeColumns(a, original);
    for (frame, original[0].values) |x, y| try std.testing.expectEqual(y.v, x);
}
