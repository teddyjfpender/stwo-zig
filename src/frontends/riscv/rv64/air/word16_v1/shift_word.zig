//! Inactive Word16 SHIFT candidate. Same function truth and pure chunk algebra
//! as the byte control; its distinct million-row table is part of the cost.
const std = @import("std");
const E = @import("../evaluation.zig");
const Ops = @import("operations.zig");
const Arithmetic = @import("shift_chunk_arithmetic.zig");
const Table = @import("shift_word_table.zig");
pub const LOCAL_MAIN = 52;
pub const CONSTRAINTS = 27;
pub const TABLE_QUERIES = 5;
pub const RANGE_QUERIES = 9;
pub const nativeResult = Arithmetic.nativeResult;
pub fn RowFor(comptime F: type) type {
    return struct {
        payload: [13]F,
        active: F,
        selectors: [6]F,
        table_outputs: [5][4]F,
        amount: F,
        offset: [4]F,
        quotient: F,
        ignored_w_bit: F,
        sign: [3]F,
        fill: [2]F,
    };
}
pub fn rowFromColumnsFor(comptime F: type, values: []const F) RowFor(F) {
    std.debug.assert(values.len >= LOCAL_MAIN);
    var row: RowFor(F) = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(RowFor(F))) |field| {
        if (field.type == [5][4]F) {
            for (&row.table_outputs) |*tuple| {
                tuple.* = values[cursor..][0..4].*;
                cursor += 4;
            }
        } else if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @field(row, field.name) = values[cursor..][0..n].*;
            cursor += n;
        } else {
            @field(row, field.name) = values[cursor];
            cursor += 1;
        }
    }
    std.debug.assert(cursor == LOCAL_MAIN);
    return row;
}
pub fn rowToColumnsFor(comptime F: type, row: *const RowFor(F)) [LOCAL_MAIN]F {
    var values: [LOCAL_MAIN]F = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(RowFor(F))) |field| {
        if (field.type == [5][4]F) {
            for (row.table_outputs) |tuple| {
                @memcpy(values[cursor..][0..4], &tuple);
                cursor += 4;
            }
        } else if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @memcpy(values[cursor..][0..n], &@field(row, field.name));
            cursor += n;
        } else {
            values[cursor] = @field(row, field.name);
            cursor += 1;
        }
    }
    std.debug.assert(cursor == LOCAL_MAIN);
    return values;
}
pub fn tableTupleFor(comptime F: type, r: *const RowFor(F), query: usize) [6]F {
    std.debug.assert(query < TABLE_QUERIES);
    return .{ if (query < 4) r.payload[1 + query] else E.qFor(F, 65535), r.amount, r.table_outputs[query][0], r.table_outputs[query][1], r.table_outputs[query][2], r.table_outputs[query][3] };
}
pub fn rangeValueFor(comptime F: type, r: *const RowFor(F), query: usize) F {
    std.debug.assert(query < RANGE_QUERIES);
    if (query < 4) return r.payload[5 + query];
    if (query == 4) return r.quotient;
    if (query == 5) return r.quotient.mul(E.qFor(F, 64));
    const limb = switch (query) {
        6 => r.payload[2],
        7 => r.payload[4],
        8 => r.payload[10],
        else => unreachable,
    };
    return limb.mul(E.qFor(F, 2)).sub(r.sign[query - 6].mul(E.qFor(F, 65536)));
}
pub fn emitFor(comptime F: type, r: *const RowFor(F), sink: anytype) void {
    Arithmetic.emitHeadFor(F, 16, r, sink);
    Arithmetic.emitSignsFor(F, r, sink);
    for (0..4) |i| sink.emit(r.payload[9 + i].sub(Arithmetic.resultFor(F, 16, r, i)));
}
pub fn witness(op: Ops.Shift, a: u64, b: u64) RowFor(E.Q) {
    const F = E.Q;
    var r: RowFor(F) = undefined;
    r.active = F.one();
    r.payload[0] = E.q(Ops.busIdFor(.shift, @intFromEnum(op)));
    r.selectors = @splat(F.zero());
    r.selectors[@intFromEnum(op)] = F.one();
    const c = nativeResult(op, a, b);
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        r.payload[1 + i] = E.q(@as(u16, @truncate(a >> shift)));
        r.payload[5 + i] = E.q(@as(u16, @truncate(b >> shift)));
        r.payload[9 + i] = E.q(@as(u16, @truncate(c >> shift)));
    }
    const word = @intFromEnum(op) >= 3;
    r.amount = E.q(@intCast(b & 15));
    r.offset = @splat(F.zero());
    r.offset[(b >> 4) & @as(u64, if (word) 1 else 3)] = F.one();
    r.quotient = E.q(@as(u16, @truncate(b)) >> 6);
    r.ignored_w_bit = E.q(if (word) @intCast((b >> 5) & 1) else 0);
    r.sign = .{ E.q(@intCast((a >> 31) & 1)), E.q(@intCast(a >> 63)), E.q(@intCast((c >> 31) & 1)) };
    r.fill = .{ if (op == .sra) r.sign[1] else F.zero(), if (op == .sraw) r.sign[0] else F.zero() };
    for (0..5) |i| {
        const limb: u32 = if (i == 4) 65535 else @as(u16, @truncate(a >> @as(u6, @intCast(16 * i))));
        const tuple = Table.tupleAt(limb * 16 + @as(usize, @intCast(b & 15)));
        for (0..4) |j| r.table_outputs[i][j] = E.q(tuple[2 + j]);
    }
    return r;
}
