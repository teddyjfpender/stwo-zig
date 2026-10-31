//! Inactive byte-interface SHIFT arithmetic prototype. Accepting it also requires
//! nine full SHIFT-table memberships, nine U16 memberships and FUNCTION closure.
const std = @import("std");
const E = @import("../evaluation.zig");
const Arithmetic = @import("shift_chunk_arithmetic.zig");
const Ops = @import("operations.zig");
const Tables = @import("../providers/tables.zig");
pub const LOCAL_MAIN = 88;
pub const CONSTRAINTS = 43;
pub const TABLE_QUERIES = 9;
pub const RANGE_QUERIES = 9;

pub fn RowFor(comptime F: type) type {
    return struct {
        payload: [13]F,
        active: F,
        selectors: [6]F,
        input_bytes: [8]F,
        table_outputs: [9][4]F,
        output_bytes: [8]F,
        amount: F,
        offset: [8]F,
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
        if (field.type == [9][4]F) {
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
        if (field.type == [9][4]F) {
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
    return .{ if (query < 8) r.input_bytes[query] else E.qFor(F, 255), r.amount, r.table_outputs[query][0], r.table_outputs[query][1], r.table_outputs[query][2], r.table_outputs[query][3] };
}

pub fn rangeValueFor(comptime F: type, r: *const RowFor(F), query: usize) F {
    std.debug.assert(query < RANGE_QUERIES);
    if (query < 4) return r.payload[5 + query];
    if (query == 4) return r.quotient;
    if (query == 5) return r.quotient.mul(E.qFor(F, 64));
    const chunk = switch (query) {
        6 => r.input_bytes[3],
        7 => r.input_bytes[7],
        8 => r.output_bytes[3],
        else => unreachable,
    };
    // SHIFT membership (or the proved disjoint-output construction) first makes
    // this a canonical byte. Scaled range alone is not a byte-range argument.
    return chunk.mul(E.qFor(F, 512)).sub(r.sign[query - 6].mul(E.qFor(F, 65536)));
}

pub fn emitFor(comptime F: type, r: *const RowFor(F), sink: anytype) void {
    Arithmetic.emitHeadFor(F, 8, r, sink);
    for (0..4) |i| {
        sink.emit(r.payload[1 + i].sub(r.input_bytes[2 * i]).sub(r.input_bytes[2 * i + 1].mul(E.qFor(F, 256))));
        sink.emit(r.payload[9 + i].sub(r.output_bytes[2 * i]).sub(r.output_bytes[2 * i + 1].mul(E.qFor(F, 256))));
    }
    Arithmetic.emitSignsFor(F, r, sink);
    for (0..8) |i| sink.emit(r.output_bytes[i].sub(Arithmetic.resultFor(F, 8, r, i)));
}

pub const nativeResult = Arithmetic.nativeResult;

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
    r.amount = E.q(@intCast(b & 7));
    r.offset = @splat(F.zero());
    r.offset[(b >> 3) & @as(u64, if (word) 3 else 7)] = F.one();
    r.quotient = E.q(@as(u16, @truncate(b)) >> 6);
    r.ignored_w_bit = E.q(if (word) @intCast((b >> 5) & 1) else 0);
    r.sign = .{ E.q(@intCast((a >> 31) & 1)), E.q(@intCast(a >> 63)), E.q(@intCast((c >> 31) & 1)) };
    r.fill = .{ if (op == .sra) r.sign[1] else F.zero(), if (op == .sraw) r.sign[0] else F.zero() };
    for (0..8) |i| {
        const shift: u6 = @intCast(8 * i);
        r.input_bytes[i] = E.q(@as(u8, @truncate(a >> shift)));
        r.output_bytes[i] = E.q(@as(u8, @truncate(c >> shift)));
    }
    for (0..9) |i| {
        const byte: u32 = if (i == 8) 255 else @as(u8, @truncate(a >> @as(u6, @intCast(8 * i))));
        const tuple = Tables.Kind.byte_shift.tupleAt(byte * 8 + @as(usize, @intCast(b & 7)));
        for (0..4) |j| r.table_outputs[i][j] = E.q(tuple[2 + j]);
    }
    return r;
}
