//! Fixed AIR relation between a published global span and its native local leaf.
//! The shared V3 map owns projection; integer witnesses prove the global u64
//! range without reducing it into one M31 element. No leaf value is a constant.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const arithmetic = frontend.recursion.arithmetic_circuit;
const span = frontend.recursion.span_statement;
const projection = frontend.recursion.segment_leaf_local_projection_v3;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Value = arithmetic.Value;
pub const VERSION: u16 = 1;
pub const WORD_COUNT = span.SPAN_STATEMENT_CANONICAL_WORDS;
pub const AUX_COUNT: usize = 4 * 64 + 6 + 2;
pub const Integer = enum(u2) { start, end, total, remaining };
pub const AuxSource = union(enum) {
    bit: struct { integer: Integer, bit: u6 },
    carry: struct { addition: u1, limb: u2 },
    initial_limb_inverse: u1,
};
pub fn sourceAt(index: usize) !AuxSource {
    if (index < 256) return .{ .bit = .{ .integer = @enumFromInt(index / 64), .bit = @intCast(index % 64) } };
    if (index < 262) return .{ .carry = .{ .addition = @intCast((index - 256) / 3), .limb = @intCast((index - 256) % 3) } };
    if (index < AUX_COUNT) return .{ .initial_limb_inverse = @intCast(index - 262) };
    return error.InvalidGlobalProjectionInput;
}
pub fn auxValue(source: AuxSource, words: *const [WORD_COUNT]u32) !QM31 {
    const start = try integer(words, span.canonical_layout.first_cycle_start);
    const count = try integer(words, span.canonical_layout.executed_cycle_count_start);
    const total = try integer(words, span.canonical_layout.total_cycles_start);
    const end = try std.math.add(u64, start, count);
    const remaining = try std.math.sub(u64, total, end);
    return switch (source) {
        .bit => |part| base(@intCast(((switch (part.integer) {
            .start => start,
            .end => end,
            .total => total,
            .remaining => remaining,
        }) >> part.bit) & 1)),
        .carry => |part| blk: {
            if (part.limb >= 3) return error.InvalidGlobalProjectionInput;
            const shift: u6 = @intCast(16 * (@as(usize, part.limb) + 1));
            const mask = (@as(u64, 1) << shift) - 1;
            const a = if (part.addition == 0) start else end;
            const b = if (part.addition == 0) count else remaining;
            break :blk base(@intCast(((a & mask) + (b & mask)) >> shift));
        },
        .initial_limb_inverse => |limb| blk: {
            const value = base(words[span.canonical_layout.first_segment_start + @as(usize, limb)]);
            break :blk if (value.isZero()) QM31.zero() else try value.inv();
        },
    };
}
pub fn constrain(builder: *arithmetic.Builder, local: []const Value, global: []const Value, aux: []const Value) !void {
    if (local.len != WORD_COUNT or global.len != WORD_COUNT or aux.len != AUX_COUNT) return error.InvalidGlobalProjectionInput;
    const layout = span.canonical_layout;
    for (local, 0..) |actual, index| {
        const expected = switch (try projection.canonicalWordSourceV1(index)) {
            .global_word => |word| global[word],
            .local_cycle_count_limb => |limb| global[layout.executed_cycle_count_start + @as(usize, limb)],
            .zero => Value.zero(),
        };
        try equal(builder, actual, expected);
    }
    for (global[layout.executed_cycle_count_start + 2 ..][0..2]) |word| try equal(builder, word, Value.zero());
    var limbs: [4][4]Value = undefined;
    for (&limbs, 0..) |*parts, number| for (parts, 0..) |*part, limb| {
        part.* = Value.zero();
        for (0..16) |bit| {
            const value = aux[number * 64 + limb * 16 + bit];
            try boolean(builder, value);
            part.* = try builder.add(part.*, try builder.mul(value, try constant(builder, @as(u32, 1) << @as(u5, @intCast(bit)))));
        }
    };
    for (0..4) |limb| {
        try equal(builder, limbs[@intFromEnum(Integer.start)][limb], global[layout.first_cycle_start + limb]);
        try equal(builder, limbs[@intFromEnum(Integer.total)][limb], global[layout.total_cycles_start + limb]);
    }
    try addition(builder, &limbs[0], global[layout.executed_cycle_count_start..][0..4], &limbs[1], aux[256..259]);
    try addition(builder, &limbs[1], &limbs[3], &limbs[2], aux[259..262]);
    // Native local validation fixes the leaf index, but global first_cycle was
    // projected away. Restore the initial-leaf condition in the AIR itself.
    var initial = Value.one();
    for (0..2) |limb| {
        const word = global[layout.first_segment_start + limb];
        const inverse = aux[262 + limb];
        const zero = try builder.sub(Value.one(), try builder.mul(word, inverse));
        try equal(builder, try builder.mul(word, zero), Value.zero());
        try equal(builder, try builder.mul(inverse, zero), Value.zero());
        initial = try builder.mul(initial, zero);
    }
    for (global[layout.first_cycle_start..][0..4]) |word| try equal(builder, try builder.mul(initial, word), Value.zero());
}
fn addition(builder: *arithmetic.Builder, a: []const Value, b: []const Value, result: []const Value, carries: []const Value) !void {
    var carry = Value.zero();
    for (0..4) |limb| {
        const next = if (limb == 3) Value.zero() else carries[limb];
        try boolean(builder, next);
        const lhs = try builder.add(try builder.add(a[limb], b[limb]), carry);
        const rhs = try builder.add(result[limb], try builder.mul(next, try constant(builder, 65536)));
        try equal(builder, lhs, rhs);
        carry = next;
    }
}
fn equal(builder: *arithmetic.Builder, a: Value, b: Value) !void {
    _ = try builder.markOutput(try builder.sub(a, b));
}
fn boolean(builder: *arithmetic.Builder, value: Value) !void {
    try equal(builder, try builder.mul(value, try builder.sub(value, Value.one())), Value.zero());
}
fn constant(builder: *arithmetic.Builder, value: u32) !Value {
    return builder.constant(base(value));
}
fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
fn integer(words: *const [WORD_COUNT]u32, start: usize) !u64 {
    var value: u64 = 0;
    for (words[start..][0..4], 0..) |word, limb| {
        if (word > 65535) return error.InvalidGlobalProjectionInput;
        value |= @as(u64, word) << @as(u6, @intCast(limb * 16));
    }
    return value;
}
