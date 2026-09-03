//! Field-generic opcode-position scan AIR for Revm-42 `analyze_legacy`.
//!
//! Every active row is one opcode position, never PUSH immediate data. The
//! direct constraints authenticate cursor advancement, PUSH counts, JUMPDEST
//! events, previous/last opcode state, and exact terminal overflow/EOF
//! padding. Source-byte memory authentication is deliberately exposed as a
//! tuple but is not connected to the production memory relation yet.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const candidate = @import("analyze_legacy_candidate_v1.zig");

pub const production_active = false;
pub const memory_relation_ready = false;
pub const maximum_constraint_degree: u8 = 9;
pub const byte_bits: usize = 8;
pub const overflow_bits: usize = 6;
pub const remaining_gap_bits: usize = 30;
pub const bitmap_tail_bits: usize = 3;
pub const descriptor_relation_arity: usize = 7;
pub const terminal_relation_arity: usize = 4;
pub const source_byte_relation_arity: usize = 4;

pub const Error = candidate.Error || error{OutOfMemory};

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        is_first: S,
        is_last: S,
        call_index: S,
        source_pointer: S,
        source_length: S,
        row_index: S,
        cursor: S,
        next_cursor: S,
        source_byte: S,
        source_byte_bits: [byte_bits]S,
        previous_opcode: S,
        previous_opcode_bits: [byte_bits]S,
        last_opcode: S,
        is_push: S,
        is_jumpdest: S,
        last_is_stop: S,
        last_is_eof_immediate: S,
        previous_is_eof_immediate: S,
        step: S,
        push_count_before: S,
        jumpdest_count_before: S,
        expected_scan_iterations: S,
        expected_push_count: S,
        expected_jumpdest_count: S,
        bitmap_bytes: S,
        push_overflow: S,
        push_overflow_bits: [overflow_bits]S,
        eof_immediate_padding: S,
        total_padding: S,
        remaining_gap_bits: [remaining_gap_bits]S,
        bitmap_tail_padding_bits: [bitmap_tail_bits]S,
    };
}

pub fn zeroRow(comptime S: type) Row(S) {
    return .{
        .active = S.zero(),
        .is_first = S.zero(),
        .is_last = S.zero(),
        .call_index = S.zero(),
        .source_pointer = S.zero(),
        .source_length = S.zero(),
        .row_index = S.zero(),
        .cursor = S.zero(),
        .next_cursor = S.zero(),
        .source_byte = S.zero(),
        .source_byte_bits = @splat(S.zero()),
        .previous_opcode = S.zero(),
        .previous_opcode_bits = @splat(S.zero()),
        .last_opcode = S.zero(),
        .is_push = S.zero(),
        .is_jumpdest = S.zero(),
        .last_is_stop = S.zero(),
        .last_is_eof_immediate = S.zero(),
        .previous_is_eof_immediate = S.zero(),
        .step = S.zero(),
        .push_count_before = S.zero(),
        .jumpdest_count_before = S.zero(),
        .expected_scan_iterations = S.zero(),
        .expected_push_count = S.zero(),
        .expected_jumpdest_count = S.zero(),
        .bitmap_bytes = S.zero(),
        .push_overflow = S.zero(),
        .push_overflow_bits = @splat(S.zero()),
        .eof_immediate_padding = S.zero(),
        .total_padding = S.zero(),
        .remaining_gap_bits = @splat(S.zero()),
        .bitmap_tail_padding_bits = @splat(S.zero()),
    };
}

pub fn materialize(
    allocator: std.mem.Allocator,
    descriptor: candidate.DescriptorV1,
    source: []const u8,
) Error![]Row(M31) {
    try descriptor.validate(source);
    const rows = try allocator.alloc(Row(M31), descriptor.summary.scan_iterations);
    errdefer allocator.free(rows);
    var cursor: u32 = 0;
    var previous: u8 = 0;
    var pushes: u32 = 0;
    var jumpdests: u32 = 0;
    for (rows, 0..) |*row, row_index| {
        const source_byte = source[cursor];
        const is_push = source_byte >= candidate.push1_opcode and
            source_byte <= candidate.push32_opcode;
        const step: u32 = if (is_push)
            @as(u32, source_byte - candidate.push1_opcode) + 2
        else
            1;
        const next_cursor = cursor + step;
        const is_last = next_cursor >= descriptor.source_length;
        const overflow = if (is_last)
            next_cursor - descriptor.source_length
        else
            0;
        const remaining = if (is_last)
            0
        else
            descriptor.source_length - next_cursor - 1;
        const jumpdest = source_byte == candidate.jumpdest_opcode;
        const eof_padding = if (is_last)
            descriptor.summary.eof_immediate_padding
        else
            0;
        row.* = zeroRow(M31);
        row.active = M31.one();
        row.is_first = feltBool(row_index == 0);
        row.is_last = feltBool(is_last);
        row.call_index = felt(descriptor.call_index);
        row.source_pointer = felt(descriptor.source_pointer);
        row.source_length = felt(descriptor.source_length);
        row.row_index = felt(@intCast(row_index));
        row.cursor = felt(cursor);
        row.next_cursor = felt(next_cursor);
        row.source_byte = felt(source_byte);
        writeBits(&row.source_byte_bits, source_byte);
        row.previous_opcode = felt(previous);
        writeBits(&row.previous_opcode_bits, previous);
        row.last_opcode = felt(source_byte);
        row.is_push = feltBool(is_push);
        row.is_jumpdest = feltBool(jumpdest);
        row.last_is_stop = feltBool(source_byte == candidate.stop_opcode);
        row.last_is_eof_immediate = feltBool(candidate.isEofImmediate(source_byte));
        row.previous_is_eof_immediate = feltBool(candidate.isEofImmediate(previous));
        row.step = felt(step);
        row.push_count_before = felt(pushes);
        row.jumpdest_count_before = felt(jumpdests);
        row.expected_scan_iterations = felt(descriptor.summary.scan_iterations);
        row.expected_push_count = felt(descriptor.summary.push_count);
        row.expected_jumpdest_count = felt(descriptor.summary.jumpdest_count);
        row.bitmap_bytes = felt(descriptor.summary.bitmap_bytes);
        row.push_overflow = felt(overflow);
        writeBits(&row.push_overflow_bits, overflow);
        row.eof_immediate_padding = felt(eof_padding);
        row.total_padding = felt(if (is_last) descriptor.summary.total_padding else 0);
        writeBits(&row.remaining_gap_bits, remaining);
        writeBits(
            &row.bitmap_tail_padding_bits,
            if (is_last)
                descriptor.summary.bitmap_bytes * 8 - descriptor.source_length
            else
                0,
        );
        pushes += @intFromBool(is_push);
        jumpdests += @intFromBool(jumpdest);
        previous = source_byte;
        cursor = next_cursor;
    }
    std.debug.assert(cursor >= descriptor.source_length);
    std.debug.assert(pushes == descriptor.summary.push_count);
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
    boolean(row.is_push, sink);
    boolean(row.is_jumpdest, sink);
    boolean(row.last_is_stop, sink);
    boolean(row.last_is_eof_immediate, sink);
    boolean(row.previous_is_eof_immediate, sink);
    for (row.source_byte_bits) |bit| boolean(bit, sink);
    for (row.previous_opcode_bits) |bit| boolean(bit, sink);
    for (row.push_overflow_bits) |bit| boolean(bit, sink);
    for (row.remaining_gap_bits) |bit| boolean(bit, sink);
    for (row.bitmap_tail_padding_bits) |bit| boolean(bit, sink);

    sink.add(active.sub(expected_active), 1);
    sink.add(row.is_first.mul(one.sub(active)), 2);
    sink.add(row.is_last.mul(one.sub(active)), 2);
    sink.add(trace_first.mul(active.sub(row.is_first)), 2);
    constrainPadding(S, row, padding, sink);

    const source_value = composeBits(S, &row.source_byte_bits);
    const previous_value = composeBits(S, &row.previous_opcode_bits);
    sink.add(row.source_byte.sub(source_value), 1);
    sink.add(row.previous_opcode.sub(previous_value), 1);
    sink.add(row.last_opcode.sub(row.source_byte), 1);
    sink.add(row.is_push.sub(active.mul(
        one.sub(row.source_byte_bits[7]).mul(
            row.source_byte_bits[6],
        ).mul(row.source_byte_bits[5]),
    )), 4);
    sink.add(row.is_jumpdest.sub(active.mul(equalsByte(
        S,
        &row.source_byte_bits,
        candidate.jumpdest_opcode,
    ))), maximum_constraint_degree);
    sink.add(row.last_is_stop.sub(active.mul(equalsByte(
        S,
        &row.source_byte_bits,
        candidate.stop_opcode,
    ))), maximum_constraint_degree);
    sink.add(row.last_is_eof_immediate.sub(active.mul(eofImmediateIndicator(
        S,
        &row.source_byte_bits,
    ))), maximum_constraint_degree);
    sink.add(row.previous_is_eof_immediate.sub(active.mul(eofImmediateIndicator(
        S,
        &row.previous_opcode_bits,
    ))), maximum_constraint_degree);

    const push_offset = composeBits(S, row.source_byte_bits[0..5]);
    sink.add(row.step.sub(active.mul(
        one.add(row.is_push.mul(push_offset.add(one))),
    )), 3);
    sink.add(active.mul(
        row.next_cursor.sub(row.cursor).sub(row.step),
    ), 2);
    sink.add(row.is_first.mul(row.cursor), 2);
    sink.add(row.is_first.mul(row.row_index), 2);
    sink.add(row.is_first.mul(row.previous_opcode), 2);
    sink.add(row.is_first.mul(row.push_count_before), 2);
    sink.add(row.is_first.mul(row.jumpdest_count_before), 2);

    const remaining = composeBits(S, &row.remaining_gap_bits);
    sink.add(nonlast.mul(
        row.source_length.sub(row.next_cursor).sub(one).sub(remaining),
    ), 2);
    for (row.remaining_gap_bits) |bit| sink.add(last.mul(bit), 2);

    const overflow = composeBits(S, &row.push_overflow_bits);
    sink.add(row.push_overflow.sub(overflow), 1);
    for (row.push_overflow_bits[0..5]) |low|
        sink.add(row.push_overflow_bits[5].mul(low), 2);
    sink.add(nonlast.mul(row.push_overflow), 2);
    sink.add(last.mul(
        row.next_cursor.sub(row.source_length).sub(row.push_overflow),
    ), 2);
    sink.add(nonlast.mul(row.eof_immediate_padding), 2);
    sink.add(nonlast.mul(row.total_padding), 2);
    sink.add(row.eof_immediate_padding.mul(
        row.eof_immediate_padding.sub(one),
    ).mul(row.eof_immediate_padding.sub(fromU32(S, 2))), 3);
    const expected_eof = row.last_is_stop.mul(
        row.previous_is_eof_immediate,
    ).add(one.sub(row.last_is_stop).mul(
        one.add(row.last_is_eof_immediate),
    ));
    sink.add(last.mul(row.eof_immediate_padding.sub(expected_eof)), 3);
    sink.add(last.mul(
        row.total_padding.sub(row.push_overflow).sub(row.eof_immediate_padding),
    ), 2);

    const bitmap_tail = composeBits(S, &row.bitmap_tail_padding_bits);
    for (row.bitmap_tail_padding_bits) |bit| sink.add(nonlast.mul(bit), 2);
    sink.add(last.mul(
        mulSmall(S, row.bitmap_bytes, 8)
            .sub(row.source_length)
            .sub(bitmap_tail),
    ), 2);
    sink.add(last.mul(
        row.row_index.add(one).sub(row.expected_scan_iterations),
    ), 2);
    sink.add(last.mul(
        row.push_count_before.add(row.is_push).sub(row.expected_push_count),
    ), 2);
    sink.add(last.mul(
        row.jumpdest_count_before.add(row.is_jumpdest).sub(
            row.expected_jumpdest_count,
        ),
    ), 2);

    sink.add(nonlast.mul(one.sub(next_expected_active)), 2);
    sink.add(nonlast.mul(one.sub(next.active)), 2);
    sink.add(nonlast.mul(next.is_first), 2);
    sameOnContinuation(S, nonlast, row, next, sink);
    sink.add(nonlast.mul(next.row_index.sub(row.row_index).sub(one)), 2);
    sink.add(nonlast.mul(next.cursor.sub(row.next_cursor)), 2);
    sink.add(nonlast.mul(next.previous_opcode.sub(row.source_byte)), 2);
    sink.add(nonlast.mul(
        next.push_count_before.sub(row.push_count_before).sub(row.is_push),
    ), 2);
    sink.add(nonlast.mul(
        next.jumpdest_count_before.sub(row.jumpdest_count_before).sub(
            row.is_jumpdest,
        ),
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
        row.source_pointer,
        row.source_length,
        row.bitmap_bytes,
        row.expected_scan_iterations,
        row.expected_push_count,
        row.expected_jumpdest_count,
    };
}

pub fn TerminalTupleFor(comptime S: type) type {
    return [terminal_relation_arity]S;
}

pub fn terminalTuple(comptime S: type, row: *const Row(S)) TerminalTupleFor(S) {
    return .{
        row.call_index,
        row.push_overflow,
        row.eof_immediate_padding,
        row.total_padding,
    };
}

pub fn SourceByteTupleFor(comptime S: type) type {
    return [source_byte_relation_arity]S;
}

pub fn sourceByteTuple(
    comptime S: type,
    row: *const Row(S),
) SourceByteTupleFor(S) {
    return .{
        row.call_index,
        row.source_pointer.add(row.cursor),
        row.cursor,
        row.source_byte,
    };
}

fn sameOnContinuation(
    comptime S: type,
    gate: S,
    row: *const Row(S),
    next: *const Row(S),
    sink: anytype,
) void {
    inline for (.{
        "call_index",
        "source_pointer",
        "source_length",
        "expected_scan_iterations",
        "expected_push_count",
        "expected_jumpdest_count",
        "bitmap_bytes",
    }) |name| sink.add(gate.mul(
        @field(next, name).sub(@field(row, name)),
    ), 2);
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

fn equalsByte(comptime S: type, bits: *const [byte_bits]S, value: u8) S {
    var result = S.one();
    for (bits, 0..) |bit, index| result = result.mul(
        if (value >> @intCast(index) & 1 == 1) bit else S.one().sub(bit),
    );
    return result;
}

fn eofImmediateIndicator(comptime S: type, bits: *const [byte_bits]S) S {
    return equalsByte(S, bits, candidate.dupn_opcode)
        .add(equalsByte(S, bits, candidate.dupn_opcode + 1))
        .add(equalsByte(S, bits, candidate.dupn_opcode + 2));
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

fn mulSmall(comptime S: type, value: S, scalar: u32) S {
    return value.mul(fromU32(S, scalar));
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

fn writeBits(destination: anytype, value: anytype) void {
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
        memory_relation_ready or
        maximum_constraint_degree != 9 or
        source_byte_relation_arity != 4)
    {
        @compileError("analyze_legacy scan AIR drifted");
    }
}
