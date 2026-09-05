//! GLV width-5 wNAF scalar-program AIR.
//!
//! Rows run from the highest non-zero digit down to bit zero. Four signed
//! 128-bit wNAF streams share one doubling and up to four additions per row.
//! The component consumes two authenticated GLV splits, signed table entries,
//! and exact affine transitions, then emits one complete double-scalar program
//! tuple for the ECDSA layer.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const scalar_count: usize = 4;
pub const digit_count: usize = affine.signed_table_size;
pub const magnitude_bytes: usize = field.limb_count / 2;
pub const transition_count: usize = 5;
pub const carry_positions: usize = magnitude_bytes + 1;
pub const carry_bits_per_position: usize = 2;

pub const digit_values = [digit_count]i8{
    0,
    1,
    3,
    5,
    7,
    9,
    11,
    13,
    15,
    -1,
    -3,
    -5,
    -7,
    -9,
    -11,
    -13,
    -15,
};

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const is_first: usize = 1;
    pub const is_last: usize = 2;
    pub const bit_index: usize = 3;
    pub const digit_selectors: usize = 4;
    pub const transition_kinds: usize = digit_selectors + scalar_count * digit_count;
    pub const generator_scalar: usize = transition_kinds + transition_count;
    pub const point_scalar: usize = generator_scalar + field.limb_count;
    pub const program_point: usize = point_scalar + field.limb_count;
    pub const magnitudes: usize = program_point + relations_mod.encoded_point_size;
    pub const signs: usize = magnitudes + scalar_count * magnitude_bytes;
    pub const state_after: usize = signs + scalar_count;
    pub const carry_bits: usize = state_after + scalar_count * magnitude_bytes;
    pub const accumulator_before: usize = carry_bits +
        scalar_count * carry_positions * carry_bits_per_position;
    pub const after_double: usize = accumulator_before + relations_mod.encoded_point_size;
    pub const after_add: usize = after_double + relations_mod.encoded_point_size;
    pub const selected: usize = after_add +
        scalar_count * relations_mod.encoded_point_size;
    pub const main_columns: usize = selected +
        scalar_count * relations_mod.encoded_point_size;

    pub fn digitSelector(scalar_index: usize, code: usize) usize {
        return digit_selectors + scalar_index * digit_count + code;
    }

    pub fn transitionKind(index: usize) usize {
        return transition_kinds + index;
    }

    pub fn magnitude(scalar_index: usize) usize {
        return magnitudes + scalar_index * magnitude_bytes;
    }

    pub fn sign(scalar_index: usize) usize {
        return signs + scalar_index;
    }

    pub fn state(scalar_index: usize) usize {
        return state_after + scalar_index * magnitude_bytes;
    }

    pub fn carryBit(scalar_index: usize, position: usize, bit: usize) usize {
        return carry_bits +
            (scalar_index * carry_positions + position) * carry_bits_per_position + bit;
    }

    pub fn afterAdd(scalar_index: usize) usize {
        return after_add + scalar_index * relations_mod.encoded_point_size;
    }

    pub fn selectedPoint(scalar_index: usize) usize {
        return selected + scalar_index * relations_mod.encoded_point_size;
    }
};

pub const event_count: usize = 14;
pub const batch_count: usize = event_count / 2;
/// Only the recurrence state is private to this row family. Scalars and
/// points are inherited through split/table/point/program relations whose
/// providers already own byte custody.
pub const range_pair_count: usize = scalar_count * magnitude_bytes / 2;
pub const maximum_constraint_degree: u8 = 2;
pub const constraint_count: usize = 1134;

pub const Error = error{
    InvalidProgramRange,
    InvalidStep,
    InvalidTransition,
    InvalidTableSelection,
    InvalidWnafRecurrence,
};

comptime {
    if (Layout.main_columns != 1124 or batch_count != 7 or range_pair_count != 32)
        @compileError("secp256k1 scalar-program geometry drifted");
}

pub fn rowFromStep(
    tape: *const affine.Tape,
    program: *const affine.ScalarProgramRecord,
    ordinal: usize,
) Error![Layout.main_columns]M31 {
    if (ordinal >= program.step_count or
        program.split_start + 2 > tape.scalar_splits.items.len or
        program.table_start + scalar_count > tape.tables.items.len or
        program.step_start + program.step_count > tape.scalar_steps.items.len)
    {
        return error.InvalidProgramRange;
    }
    const step = &tape.scalar_steps.items[program.step_start + ordinal];
    const splits = tape.scalar_splits.items[program.split_start..][0..2];
    const tables = tape.tables.items[program.table_start..][0..scalar_count];
    const next = if (ordinal + 1 < program.step_count)
        &tape.scalar_steps.items[program.step_start + ordinal + 1]
    else
        null;
    if ((ordinal == 0 and step.bit_index + 1 != program.step_count) or
        (next != null and next.?.bit_index + 1 != step.bit_index) or
        (next == null and step.bit_index != 0))
    {
        return error.InvalidStep;
    }

    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    row[Layout.is_first] = M31.fromU64(@intFromBool(ordinal == 0));
    row[Layout.is_last] = M31.fromU64(@intFromBool(next == null));
    row[Layout.bit_index] = M31.fromU64(step.bit_index);
    writeValue(&row, Layout.generator_scalar, program.generator_scalar);
    writeValue(&row, Layout.point_scalar, program.point_scalar);
    writePoint(&row, Layout.program_point, program.point);
    const magnitudes = [scalar_count]affine.Value{
        splits[0].magnitude_1,
        splits[0].magnitude_2,
        splits[1].magnitude_1,
        splits[1].magnitude_2,
    };
    const signs = [scalar_count]bool{
        splits[0].negative_1,
        splits[0].negative_2,
        splits[1].negative_1,
        splits[1].negative_2,
    };
    for (0..scalar_count) |scalar_index| {
        if (!allZero(magnitudes[scalar_index][magnitude_bytes..]) or
            !allZero(step.state_after[scalar_index][magnitude_bytes..]))
        {
            return error.InvalidWnafRecurrence;
        }
        writeBytes(&row, Layout.magnitude(scalar_index), magnitudes[scalar_index][0..magnitude_bytes]);
        row[Layout.sign(scalar_index)] = M31.fromU64(@intFromBool(signs[scalar_index]));
        writeBytes(&row, Layout.state(scalar_index), step.state_after[scalar_index][0..magnitude_bytes]);
        const code = affine.signedTableIndex(step.digits[scalar_index]);
        row[Layout.digitSelector(scalar_index, code)] = M31.one();
        if (!affine.Point.eql(step.selected[scalar_index], tables[scalar_index].entries[code]))
            return error.InvalidTableSelection;
        writePoint(&row, Layout.selectedPoint(scalar_index), step.selected[scalar_index]);

        const target = if (next) |next_step|
            next_step.state_after[scalar_index]
        else
            magnitudes[scalar_index];
        try writeCarries(
            &row,
            scalar_index,
            step.state_after[scalar_index],
            target,
            if (signs[scalar_index])
                -step.digits[scalar_index]
            else
                step.digits[scalar_index],
        );
    }
    writePoint(&row, Layout.after_double, step.after_double);
    for (step.after_add, 0..) |point, scalar_index| {
        writePoint(&row, Layout.afterAdd(scalar_index), point);
    }

    const previous = if (ordinal == 0)
        affine.Point{}
    else
        tape.scalar_steps.items[program.step_start + ordinal - 1].after_add[3];
    writePoint(&row, Layout.accumulator_before, previous);
    try bindTransition(
        tape,
        step.point_record_indices[0],
        previous,
        .{},
        step.after_double,
        &row,
        0,
    );
    var accumulator = step.after_double;
    for (0..scalar_count) |scalar_index| {
        const digit = step.digits[scalar_index];
        if (digit == 0) {
            if (step.point_record_indices[1 + scalar_index] != std.math.maxInt(u32) or
                !affine.Point.eql(accumulator, step.after_add[scalar_index]))
            {
                return error.InvalidTransition;
            }
        } else {
            try bindTransition(
                tape,
                step.point_record_indices[1 + scalar_index],
                accumulator,
                step.selected[scalar_index],
                step.after_add[scalar_index],
                &row,
                1 + scalar_index,
            );
        }
        accumulator = step.after_add[scalar_index];
    }
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    previous: *const [Layout.main_columns]S,
    next: *const [Layout.main_columns]S,
    expected_first: S,
    expected_last: S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const first = main[Layout.is_first];
    const last = main[Layout.is_last];
    const one = scalar(S, 1);
    _ = expected_first;
    _ = expected_last;
    sink.add(active.mul(active.sub(one)), 2);
    sink.add(first.mul(first.sub(active)), 2);
    sink.add(last.mul(last.sub(active)), 2);
    // Program boundaries are derived from committed neighbouring rows rather
    // than prover-selected Tree-0 markers.  This makes the preprocessed root
    // reconstructible from public geometry while retaining exact group
    // topology: an active row starts after padding or a previous last row,
    // and ends before padding or a next first row.
    sink.add(first.sub(active.mul(
        one.sub(previous[Layout.is_active]).add(previous[Layout.is_last]),
    )), 2);
    sink.add(last.sub(active.mul(
        one.sub(next[Layout.is_active]).add(next[Layout.is_first]),
    )), 2);
    sink.add(last.mul(main[Layout.bit_index]), 2);
    sink.add(active.sub(last).mul(
        main[Layout.bit_index].sub(next[Layout.bit_index].add(one)),
    ), 2);

    const header_start = Layout.generator_scalar;
    const header_end = Layout.state_after;
    for (header_start..header_end) |column| {
        sink.add(active.sub(first).mul(main[column].sub(previous[column])), 2);
    }
    const program_point = pointView(S, main, Layout.program_point);
    sink.add(active.mul(program_point[0]), 2);
    const accumulator_before = pointView(S, main, Layout.accumulator_before);
    const previous_final = pointView(S, previous, Layout.afterAdd(scalar_count - 1));
    sink.add(accumulator_before[0].sub(
        first.add(active.sub(first).mul(previous_final[0])),
    ), 2);
    for (1..relations_mod.encoded_point_size) |index| {
        sink.add(accumulator_before[index].sub(
            active.sub(first).mul(previous_final[index]),
        ), 2);
    }

    for (0..scalar_count) |scalar_index| {
        var selector_sum = S.zero();
        for (0..digit_count) |code| {
            const selector = main[Layout.digitSelector(scalar_index, code)];
            sink.add(selector.mul(selector.sub(active)), 2);
            selector_sum = selector_sum.add(selector);
        }
        sink.add(selector_sum.sub(active), 1);
        const zero_selector = main[Layout.digitSelector(scalar_index, 0)];
        const selected = pointView(S, main, Layout.selectedPoint(scalar_index));
        sink.add(selected[0].sub(zero_selector), 1);
        for (selected[1..]) |coordinate| sink.add(zero_selector.mul(coordinate), 2);

        const before_add = if (scalar_index == 0)
            pointView(S, main, Layout.after_double)
        else
            pointView(S, main, Layout.afterAdd(scalar_index - 1));
        const after_add = pointView(S, main, Layout.afterAdd(scalar_index));
        for (0..relations_mod.encoded_point_size) |index| {
            sink.add(zero_selector.mul(after_add[index].sub(before_add[index])), 2);
        }

        var positive_digit = S.zero();
        var negative_digit = S.zero();
        for (1..digit_count) |code| {
            const magnitude: u64 = @intCast(if (digit_values[code] < 0)
                -@as(i16, digit_values[code])
            else
                digit_values[code]);
            const term = main[Layout.digitSelector(scalar_index, code)]
                .mul(scalar(S, magnitude));
            if (digit_values[code] < 0)
                negative_digit = negative_digit.add(term)
            else
                positive_digit = positive_digit.add(term);
        }
        const sign = main[Layout.sign(scalar_index)];
        const unsigned_positive = active.sub(sign).mul(positive_digit)
            .add(sign.mul(negative_digit));
        const unsigned_negative = active.sub(sign).mul(negative_digit)
            .add(sign.mul(positive_digit));
        for (0..carry_positions) |position| {
            inline for (0..carry_bits_per_position) |bit| {
                const carry_bit = main[Layout.carryBit(scalar_index, position, bit)];
                sink.add(carry_bit.mul(carry_bit.sub(active)), 2);
            }
        }
        sink.add(carryValue(S, main, scalar_index, 0), 1);
        sink.add(carryValue(S, main, scalar_index, magnitude_bytes), 1);
        for (0..magnitude_bytes) |byte| {
            const target = last.mul(main[Layout.magnitude(scalar_index) + byte])
                .add(active.sub(last).mul(next[Layout.state(scalar_index) + byte]));
            var equality = main[Layout.state(scalar_index) + byte].mul(scalar(S, 2))
                .sub(target)
                .add(carryValue(S, main, scalar_index, byte))
                .sub(carryValue(S, main, scalar_index, byte + 1).mul(scalar(S, 256)));
            if (byte == 0) equality = equality.add(unsigned_positive).sub(unsigned_negative);
            sink.add(equality, 2);
            sink.add(first.mul(main[Layout.state(scalar_index) + byte]), 2);
        }
    }
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    previous: *const [Layout.main_columns]S,
    relations: anytype,
) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    comptime requireSupportedField(S);
    _ = previous;
    const active = main[Layout.is_active];
    const first = main[Layout.is_first];
    const last = main[Layout.is_last];
    const generator_scalar = valueView(S, main, Layout.generator_scalar);
    const point_scalar = valueView(S, main, Layout.point_scalar);
    const program_point = pointView(S, main, Layout.program_point);
    const accumulator_before = pointView(S, main, Layout.accumulator_before);
    const identity: [relations_mod.encoded_point_size]S = blk: {
        var point: [relations_mod.encoded_point_size]S = @splat(S.zero());
        point[0] = scalar(S, 1);
        break :blk point;
    };
    const after_double = pointView(S, main, Layout.after_double);

    var events: [event_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
    const split_0 = splitTuple(S, main, 0, &generator_scalar);
    const split_1 = splitTuple(S, main, 2, &point_scalar);
    events[0] = request(S, first, relations_mod.combineSplit(S, relations.split, split_0));
    events[1] = request(S, first, relations_mod.combineSplit(S, relations.split, split_1));
    for (0..scalar_count) |scalar_index| {
        const nonzero = active.sub(main[Layout.digitSelector(scalar_index, 0)]);
        const code = digitCode(S, main, scalar_index);
        const selected = pointView(S, main, Layout.selectedPoint(scalar_index));
        const table_tuple = relations_mod.tableTuple(
            S,
            scalar(S, scalar_index),
            code,
            &selected,
        );
        events[2 + scalar_index] = request(
            S,
            nonzero,
            relations_mod.combineTable(S, relations.table, table_tuple),
        );
    }
    const public_root = relations_mod.tableRootTuple(
        S,
        scalar(S, @intFromEnum(affine.TableKind.public_key)),
        &program_point,
    );
    const endomorphism_root = relations_mod.tableRootTuple(
        S,
        scalar(S, @intFromEnum(affine.TableKind.public_key_endomorphism)),
        &program_point,
    );
    events[6] = emit(
        S,
        first,
        relations_mod.combineTableRoot(S, relations.table_root, public_root),
    );
    events[7] = emit(
        S,
        first,
        relations_mod.combineTableRoot(S, relations.table_root, endomorphism_root),
    );
    events[8] = pointRequest(
        S,
        active,
        main[Layout.transitionKind(0)],
        &accumulator_before,
        &identity,
        &after_double,
        relations,
    );
    for (0..scalar_count) |scalar_index| {
        const nonzero = active.sub(main[Layout.digitSelector(scalar_index, 0)]);
        const before = if (scalar_index == 0)
            after_double
        else
            pointView(S, main, Layout.afterAdd(scalar_index - 1));
        const selected = pointView(S, main, Layout.selectedPoint(scalar_index));
        const after = pointView(S, main, Layout.afterAdd(scalar_index));
        events[9 + scalar_index] = pointRequest(
            S,
            nonzero,
            main[Layout.transitionKind(1 + scalar_index)],
            &before,
            &selected,
            &after,
            relations,
        );
    }
    const final_result = pointView(S, main, Layout.afterAdd(scalar_count - 1));
    const program_tuple = relations_mod.programTuple(
        S,
        &generator_scalar,
        &program_point,
        &point_scalar,
        &final_result,
    );
    events[13] = emit(
        S,
        last,
        relations_mod.combineProgram(S, relations.program, program_tuple),
    );
    var result: [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
    for (&result, 0..) |*pair, index| pair.* = .{
        .n1 = events[2 * index].n1,
        .d1 = events[2 * index].d1,
        .n2 = events[2 * index + 1].n1,
        .d2 = events[2 * index + 1].d1,
    };
    return result;
}

pub fn rangePairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
) [range_pair_count][2]S {
    comptime requireSupportedField(S);
    var result: [range_pair_count][2]S = undefined;
    for (&result, 0..) |*pair, index| {
        const offset = Layout.state_after + 2 * index;
        pair.* = .{ main[offset], main[offset + 1] };
    }
    return result;
}

fn writeCarries(
    row: *[Layout.main_columns]M31,
    scalar_index: usize,
    state_after: affine.Value,
    target: affine.Value,
    digit: i8,
) Error!void {
    var carry: i16 = 0;
    writeCarry(row, scalar_index, 0, carry);
    for (0..magnitude_bytes) |byte| {
        const signed_digit: i16 = if (byte == 0) digit else 0;
        const coefficient = 2 * @as(i16, state_after[byte]) + signed_digit + carry -
            @as(i16, target[byte]);
        if (@mod(coefficient, 256) != 0) return error.InvalidWnafRecurrence;
        carry = @divExact(coefficient, 256);
        if (carry < -1 or carry > 2) return error.InvalidWnafRecurrence;
        writeCarry(row, scalar_index, byte + 1, carry);
    }
    if (carry != 0) return error.InvalidWnafRecurrence;
}

fn writeCarry(
    row: *[Layout.main_columns]M31,
    scalar_index: usize,
    position: usize,
    carry: i16,
) void {
    const code: u2 = @intCast(carry + 1);
    row[Layout.carryBit(scalar_index, position, 0)] = M31.fromU64(code & 1);
    row[Layout.carryBit(scalar_index, position, 1)] = M31.fromU64(code >> 1);
}

fn bindTransition(
    tape: *const affine.Tape,
    record_index: u32,
    lhs: affine.Point,
    rhs: affine.Point,
    result: affine.Point,
    row: *[Layout.main_columns]M31,
    transition_index: usize,
) Error!void {
    if (record_index >= tape.points.items.len) return error.InvalidTransition;
    const record = &tape.points.items[record_index];
    if (!affine.Point.eql(record.lhs, lhs) or
        !affine.Point.eql(record.rhs, rhs) or
        !affine.Point.eql(record.result, result))
    {
        return error.InvalidTransition;
    }
    row[Layout.transitionKind(transition_index)] = M31.fromU64(@intFromEnum(record.kind));
}

fn splitTuple(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    first_scalar: usize,
    original: *const [field.limb_count]S,
) relations_mod.SplitTuple(S) {
    const magnitude_1 = fullMagnitude(S, main, first_scalar);
    const magnitude_2 = fullMagnitude(S, main, first_scalar + 1);
    return relations_mod.splitTuple(
        S,
        main[Layout.sign(first_scalar)],
        main[Layout.sign(first_scalar + 1)],
        original,
        &magnitude_1,
        &magnitude_2,
    );
}

fn fullMagnitude(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    scalar_index: usize,
) [field.limb_count]S {
    var result: [field.limb_count]S = @splat(S.zero());
    @memcpy(result[0..magnitude_bytes], main[Layout.magnitude(scalar_index)..][0..magnitude_bytes]);
    return result;
}

fn pointRequest(
    comptime S: type,
    coefficient: S,
    kind: S,
    lhs: *const [relations_mod.encoded_point_size]S,
    rhs: *const [relations_mod.encoded_point_size]S,
    result: *const [relations_mod.encoded_point_size]S,
    relations: anytype,
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    const tuple = relations_mod.pointTuple(S, kind, lhs, rhs, result);
    return request(S, coefficient, relations_mod.combinePoint(S, relations.point, tuple));
}

fn digitCode(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    scalar_index: usize,
) S {
    var result = S.zero();
    for (0..digit_count) |code| result = result.add(
        main[Layout.digitSelector(scalar_index, code)].mul(scalar(S, code)),
    );
    return result;
}

fn carryValue(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    scalar_index: usize,
    position: usize,
) S {
    return main[Layout.carryBit(scalar_index, position, 0)]
        .add(main[Layout.carryBit(scalar_index, position, 1)].mul(scalar(S, 2)))
        .sub(main[Layout.is_active]);
}

fn pointView(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
) [relations_mod.encoded_point_size]S {
    return main[offset..][0..relations_mod.encoded_point_size].*;
}

fn valueView(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
) [field.limb_count]S {
    return main[offset..][0..field.limb_count].*;
}

fn request(
    comptime S: type,
    coefficient: S,
    denominator: relations_mod.InteractionScalar(S),
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        lift(S, coefficient).neg(),
        denominator,
    );
}

fn emit(
    comptime S: type,
    coefficient: S,
    denominator: relations_mod.InteractionScalar(S),
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        lift(S, coefficient),
        denominator,
    );
}

fn lift(comptime S: type, value: S) relations_mod.InteractionScalar(S) {
    if (S == M31) return QM31.fromBase(value);
    if (S == QM31) return value;
    return value;
}

fn scalar(comptime S: type, value: anytype) S {
    const canonical: u64 = @intCast(value);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    if (@hasDecl(S, "fromBase")) return S.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 scalar AIR requires a base-field lift");
}

fn writePoint(row: *[Layout.main_columns]M31, offset: usize, point: affine.Point) void {
    row[offset] = M31.fromU64(@intFromBool(point.infinity));
    writeValue(row, offset + 1, point.x);
    writeValue(row, offset + 1 + field.limb_count, point.y);
}

fn writeValue(row: *[Layout.main_columns]M31, offset: usize, value: affine.Value) void {
    writeBytes(row, offset, &value);
}

fn writeBytes(row: *[Layout.main_columns]M31, offset: usize, bytes: []const u8) void {
    for (bytes, 0..) |byte, index| row[offset + index] = M31.fromU64(byte);
}

fn copyBytes(
    comptime S: type,
    destination: []S,
    cursor: *usize,
    source: []const S,
) void {
    @memcpy(destination[cursor.*..][0..source.len], source);
    cursor.* += source.len;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31 and !@hasDecl(S, "fromBase"))
        @compileError("secp256k1 scalar AIR requires a base-field lift");
}
