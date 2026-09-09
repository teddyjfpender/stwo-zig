//! Field-generic JUMPDEST bitmap-word AIR for Revm-42 `analyze_legacy`.
//!
//! One active row owns 32 source-byte positions. Boolean valid bits form a
//! nonempty prefix, boolean bitmap bits are zero outside that prefix, and every
//! set bit is exported to the diagnostic JUMPDEST relation. The last row binds
//! the exact source length and `ceil(length / 8)` bitmap byte length.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const candidate = @import("analyze_legacy_candidate_v1.zig");

pub const production_active = false;
pub const interaction_component_ready = false;
pub const maximum_constraint_degree: u8 = 3;
pub const bits_per_word: usize = 32;
pub const bitmap_tail_bits: usize = 3;
pub const descriptor_relation_arity: usize = 5;
pub const jumpdest_relation_arity: usize = 2;
pub const Error = candidate.Error || error{OutOfMemory};

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        is_first: S,
        is_last: S,
        call_index: S,
        source_length: S,
        bitmap_bytes: S,
        expected_jumpdest_count: S,
        word_index: S,
        valid_bits: [bits_per_word]S,
        bitmap_bits: [bits_per_word]S,
        bitmap_tail_padding_bits: [bitmap_tail_bits]S,
    };
}

pub fn zeroRow(comptime S: type) Row(S) {
    return .{
        .active = S.zero(),
        .is_first = S.zero(),
        .is_last = S.zero(),
        .call_index = S.zero(),
        .source_length = S.zero(),
        .bitmap_bytes = S.zero(),
        .expected_jumpdest_count = S.zero(),
        .word_index = S.zero(),
        .valid_bits = @splat(S.zero()),
        .bitmap_bits = @splat(S.zero()),
        .bitmap_tail_padding_bits = @splat(S.zero()),
    };
}

pub fn materialize(
    allocator: std.mem.Allocator,
    descriptor: candidate.DescriptorV1,
    source: []const u8,
) Error![]Row(M31) {
    try descriptor.validate(source);
    const word_count = descriptor.bitmapWordRows();
    const rows = try allocator.alloc(Row(M31), word_count);
    errdefer allocator.free(rows);
    for (rows, 0..) |*row, word_index| {
        row.* = zeroRow(M31);
        row.active = M31.one();
        row.is_first = feltBool(word_index == 0);
        row.is_last = feltBool(word_index + 1 == word_count);
        row.call_index = felt(descriptor.call_index);
        row.source_length = felt(descriptor.source_length);
        row.bitmap_bytes = felt(descriptor.summary.bitmap_bytes);
        row.expected_jumpdest_count = felt(descriptor.summary.jumpdest_count);
        row.word_index = felt(@intCast(word_index));
        for (0..bits_per_word) |bit| {
            const position = word_index * bits_per_word + bit;
            row.valid_bits[bit] = feltBool(position < source.len);
        }
        if (word_index + 1 == word_count) writeBits(
            &row.bitmap_tail_padding_bits,
            descriptor.summary.bitmap_bytes * 8 - descriptor.source_length,
        );
    }

    var cursor: usize = 0;
    var jumpdests: u32 = 0;
    while (cursor < source.len) {
        const opcode = source[cursor];
        if (opcode == candidate.jumpdest_opcode) {
            rows[cursor / bits_per_word].bitmap_bits[cursor % bits_per_word] = M31.one();
            jumpdests += 1;
        }
        const push_offset = opcode -% candidate.push1_opcode;
        cursor += if (push_offset < 32) @as(usize, push_offset) + 2 else 1;
    }
    std.debug.assert(jumpdests == descriptor.summary.jumpdest_count);
    return rows;
}

pub fn liftRow(comptime S: type, source: *const Row(M31)) Row(S) {
    var result = zeroRow(S);
    inline for (std.meta.fields(Row(M31))) |field| {
        const value = @field(source, field.name);
        switch (@typeInfo(field.type)) {
            .array => {
                for (value, 0..) |item, index|
                    @field(result, field.name)[index] = fromM31(S, item);
            },
            else => @field(result, field.name) = fromM31(S, value),
        }
    }
    return result;
}

pub fn evaluateGeneric(
    comptime S: type,
    row: *const Row(S),
    next: *const Row(S),
    expected_active: S,
    next_expected_active: S,
    trace_first: S,
    sink: anytype,
) void {
    const one = S.one();
    const active = row.active;
    const last = row.is_last;
    const nonlast = active.sub(last);
    const padding = one.sub(active);
    boolean(row.active, sink);
    boolean(row.is_first, sink);
    boolean(row.is_last, sink);
    for (row.valid_bits) |bit| boolean(bit, sink);
    for (row.bitmap_bits) |bit| boolean(bit, sink);
    for (row.bitmap_tail_padding_bits) |bit| boolean(bit, sink);
    sink.add(active.sub(expected_active), 1);
    sink.add(row.is_first.mul(one.sub(active)), 2);
    sink.add(row.is_last.mul(one.sub(active)), 2);
    sink.add(trace_first.mul(active.sub(row.is_first)), 2);
    constrainPadding(S, row, padding, sink);

    sink.add(active.mul(one.sub(row.valid_bits[0])), 2);
    for (0..bits_per_word) |bit| {
        sink.add(row.bitmap_bits[bit].mul(
            one.sub(row.valid_bits[bit]),
        ), 2);
        if (bit + 1 < bits_per_word) sink.add(
            row.valid_bits[bit + 1].mul(one.sub(row.valid_bits[bit])),
            2,
        );
        sink.add(nonlast.mul(one.sub(row.valid_bits[bit])), 2);
    }
    sink.add(row.is_first.mul(row.word_index), 2);

    var valid_count = S.zero();
    for (row.valid_bits) |bit| valid_count = valid_count.add(bit);
    sink.add(last.mul(
        mulSmall(S, row.word_index, bits_per_word)
            .add(valid_count)
            .sub(row.source_length),
    ), 2);
    const tail_padding = composeBits(S, &row.bitmap_tail_padding_bits);
    for (row.bitmap_tail_padding_bits) |bit| sink.add(nonlast.mul(bit), 2);
    sink.add(last.mul(
        mulSmall(S, row.bitmap_bytes, 8)
            .sub(row.source_length)
            .sub(tail_padding),
    ), 2);

    sink.add(nonlast.mul(one.sub(next_expected_active)), 2);
    sink.add(nonlast.mul(one.sub(next.active)), 2);
    sink.add(nonlast.mul(next.is_first), 2);
    sink.add(nonlast.mul(
        next.call_index.sub(row.call_index),
    ), 2);
    sink.add(nonlast.mul(
        next.source_length.sub(row.source_length),
    ), 2);
    sink.add(nonlast.mul(
        next.bitmap_bytes.sub(row.bitmap_bytes),
    ), 2);
    sink.add(nonlast.mul(
        next.expected_jumpdest_count.sub(row.expected_jumpdest_count),
    ), 2);
    sink.add(nonlast.mul(
        next.word_index.sub(row.word_index).sub(one),
    ), 2);

    const next_call = last.mul(next_expected_active);
    sink.add(next_call.mul(one.sub(next.active)), 3);
    sink.add(next_call.mul(one.sub(next.is_first)), 3);
    sink.add(next_call.mul(
        next.call_index.sub(row.call_index).sub(one),
    ), 3);
}

pub fn DescriptorTupleFor(comptime S: type) type {
    return [descriptor_relation_arity]S;
}

pub fn descriptorTuple(
    comptime S: type,
    row: *const Row(S),
) DescriptorTupleFor(S) {
    return .{
        row.call_index,
        row.source_length,
        row.bitmap_bytes,
        row.expected_jumpdest_count,
        row.word_index,
    };
}

pub fn JumpdestTupleFor(comptime S: type) type {
    return [jumpdest_relation_arity]S;
}

pub fn jumpdestTuple(
    comptime S: type,
    row: *const Row(S),
    bit: usize,
) JumpdestTupleFor(S) {
    std.debug.assert(bit < bits_per_word);
    return .{
        row.call_index,
        mulSmall(S, row.word_index, bits_per_word).add(fromU32(S, @intCast(bit))),
    };
}

pub fn bitmapWeight(comptime S: type, row: *const Row(S), bit: usize) S {
    std.debug.assert(bit < bits_per_word);
    return row.active.mul(row.bitmap_bits[bit]);
}

fn constrainPadding(
    comptime S: type,
    row: *const Row(S),
    padding: S,
    sink: anytype,
) void {
    inline for (std.meta.fields(Row(S))) |field| {
        const value = @field(row, field.name);
        switch (@typeInfo(field.type)) {
            .array => for (value) |item| sink.add(padding.mul(item), 2),
            else => sink.add(padding.mul(value), 2),
        }
    }
}

fn boolean(value: anytype, sink: anytype) void {
    sink.add(value.mul(value.sub(@TypeOf(value).one())), 2);
}

fn composeBits(comptime S: type, bits: []const S) S {
    var result = S.zero();
    var coefficient: u32 = 1;
    for (bits) |bit| {
        result = result.add(mulSmall(S, bit, coefficient));
        coefficient <<= 1;
    }
    return result;
}

fn mulSmall(comptime S: type, value: S, scalar: usize) S {
    return value.mul(fromU32(S, @intCast(scalar)));
}

fn fromU32(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

fn fromM31(comptime S: type, value: M31) S {
    if (comptime S == M31) return value;
    if (comptime S == QM31) return QM31.fromBase(value);
    return S.fromBase(value);
}

fn writeBits(destination: anytype, value: u32) void {
    for (destination, 0..) |*bit, index|
        bit.* = feltBool(value >> @intCast(index) & 1 != 0);
}

fn felt(value: anytype) M31 {
    return M31.fromCanonical(@intCast(value));
}

fn feltBool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

comptime {
    if (production_active or
        interaction_component_ready or
        maximum_constraint_degree != 3 or
        bits_per_word != 32)
    {
        @compileError("analyze_legacy bitmap AIR drifted");
    }
}
