//! Scalar exact constraint evaluator for one Blake round row.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");
const logup = @import("logup_constraints.zig");
const statement_mod = @import("statement.zig");

const INV16 = M31.fromCanonical(1 << 15);
const TWO = M31.fromCanonical(2);

pub fn evaluate(
    main: [geometry.ROUND_MAIN_COLUMNS]QM31,
    current: [geometry.ROUND_INTERACTION_SECURE_COLUMNS]QM31,
    previous: QM31,
    elements: *const statement_mod.AllElements,
    claimed_sum: QM31,
    log_size: u32,
) ![geometry.ROUND_CONSTRAINTS]QM31 {
    var algebraic: [geometry.ROUND_ALGEBRAIC_CONSTRAINTS]QM31 = undefined;
    var entries: [2 * geometry.ROUND_INTERACTION_SECURE_COLUMNS - 1]logup.Entry =
        undefined;
    try parse(main, elements, &algebraic, &entries);

    var constraints: [geometry.ROUND_CONSTRAINTS]QM31 = undefined;
    @memcpy(
        constraints[0..geometry.ROUND_ALGEBRAIC_CONSTRAINTS],
        &algebraic,
    );
    try logup.evaluate(
        &entries,
        &current,
        previous,
        claimed_sum,
        log_size,
        constraints[geometry.ROUND_ALGEBRAIC_CONSTRAINTS..],
    );
    return constraints;
}

pub fn algebraicConstraints(
    main: [geometry.ROUND_MAIN_COLUMNS]QM31,
    elements: *const statement_mod.AllElements,
) ![geometry.ROUND_ALGEBRAIC_CONSTRAINTS]QM31 {
    var algebraic: [geometry.ROUND_ALGEBRAIC_CONSTRAINTS]QM31 = undefined;
    var entries: [2 * geometry.ROUND_INTERACTION_SECURE_COLUMNS - 1]logup.Entry =
        undefined;
    try parse(main, elements, &algebraic, &entries);
    return algebraic;
}

fn parse(
    main: [geometry.ROUND_MAIN_COLUMNS]QM31,
    elements: *const statement_mod.AllElements,
    algebraic: *[geometry.ROUND_ALGEBRAIC_CONSTRAINTS]QM31,
    entries: *[2 * geometry.ROUND_INTERACTION_SECURE_COLUMNS - 1]logup.Entry,
) !void {
    var reader = Reader{
        .main = &main,
        .elements = elements,
        .algebraic = algebraic,
        .entries = entries,
    };
    var state: [constants.STATE_SIZE]Fu32 = undefined;
    for (&state) |*word| word.* = reader.nextU32();
    const input_state = state;
    var message: [constants.MESSAGE_SIZE]Fu32 = undefined;
    for (&message) |*word| word.* = reader.nextU32();

    reader.g(&state, .{ 0, 4, 8, 12 }, message[0], message[1]);
    reader.g(&state, .{ 1, 5, 9, 13 }, message[2], message[3]);
    reader.g(&state, .{ 2, 6, 10, 14 }, message[4], message[5]);
    reader.g(&state, .{ 3, 7, 11, 15 }, message[6], message[7]);
    reader.g(&state, .{ 0, 5, 10, 15 }, message[8], message[9]);
    reader.g(&state, .{ 1, 6, 11, 12 }, message[10], message[11]);
    reader.g(&state, .{ 2, 7, 8, 13 }, message[12], message[13]);
    reader.g(&state, .{ 3, 4, 9, 14 }, message[14], message[15]);

    var tuple: [constants.N_ROUND_INPUT_FELTS]QM31 = undefined;
    var tuple_index: usize = 0;
    appendFu32s(&tuple, &tuple_index, &input_state);
    appendFu32s(&tuple, &tuple_index, &state);
    appendFu32s(&tuple, &tuple_index, &message);
    reader.entries[reader.entry_index] = .{
        .multiplicity = QM31.one().neg(),
        .denominator = elements.round.combineSecure(&tuple),
    };
    reader.entry_index += 1;

    if (reader.main_index != geometry.ROUND_MAIN_COLUMNS or
        reader.algebraic_index != geometry.ROUND_ALGEBRAIC_CONSTRAINTS or
        reader.entry_index != reader.entries.len)
    {
        return error.InvalidPreparedGeometry;
    }
}

const Fu32 = struct {
    low: QM31,
    high: QM31,
};

const Reader = struct {
    main: *const [geometry.ROUND_MAIN_COLUMNS]QM31,
    elements: *const statement_mod.AllElements,
    algebraic: *[geometry.ROUND_ALGEBRAIC_CONSTRAINTS]QM31,
    entries: *[2 * geometry.ROUND_INTERACTION_SECURE_COLUMNS - 1]logup.Entry,
    main_index: usize = 0,
    algebraic_index: usize = 0,
    entry_index: usize = 0,

    fn next(self: *@This()) QM31 {
        const value = self.main[self.main_index];
        self.main_index += 1;
        return value;
    }

    fn nextU32(self: *@This()) Fu32 {
        return .{ .low = self.next(), .high = self.next() };
    }

    fn addConstraint(self: *@This(), constraint: QM31) void {
        self.algebraic[self.algebraic_index] = constraint;
        self.algebraic_index += 1;
    }

    fn g(
        self: *@This(),
        state: *[constants.STATE_SIZE]Fu32,
        indices: [4]usize,
        message0: Fu32,
        message1: Fu32,
    ) void {
        const a = indices[0];
        const b = indices[1];
        const c = indices[2];
        const d = indices[3];
        state[a] = self.add3(state[a], state[b], message0);
        state[d] = self.xorRotate16(state[a], state[d]);
        state[c] = self.add2(state[c], state[d]);
        state[b] = self.xorRotate(state[b], state[c], 12);
        state[a] = self.add3(state[a], state[b], message1);
        state[d] = self.xorRotate(state[a], state[d], 8);
        state[c] = self.add2(state[c], state[d]);
        state[b] = self.xorRotate(state[b], state[c], 7);
    }

    fn add2(self: *@This(), a: Fu32, b: Fu32) Fu32 {
        const low = self.next();
        const high = self.next();
        const carry_low = a.low.add(b.low).sub(low).mulM31(INV16);
        self.addConstraint(carry_low.mul(carry_low.sub(QM31.one())));
        const carry_high = a.high.add(b.high).add(carry_low).sub(high).mulM31(INV16);
        self.addConstraint(carry_high.mul(carry_high.sub(QM31.one())));
        return .{ .low = low, .high = high };
    }

    fn add3(self: *@This(), a: Fu32, b: Fu32, c: Fu32) Fu32 {
        const low = self.next();
        const high = self.next();
        const carry_low = a.low.add(b.low).add(c.low).sub(low).mulM31(INV16);
        self.addConstraint(
            carry_low.mul(carry_low.sub(QM31.one()))
                .mul(carry_low.sub(QM31.fromBase(TWO))),
        );
        const carry_high = a.high.add(b.high).add(c.high).add(carry_low)
            .sub(high).mulM31(INV16);
        self.addConstraint(
            carry_high.mul(carry_high.sub(QM31.one()))
                .mul(carry_high.sub(QM31.fromBase(TWO))),
        );
        return .{ .low = low, .high = high };
    }

    fn split(self: *@This(), value: QM31, width: u5) struct { low: QM31, high: QM31 } {
        const high = self.next();
        return .{
            .low = value.sub(high.mulM31(
                M31.fromCanonical(@as(u32, 1) << width),
            )),
            .high = high,
        };
    }

    fn xorRotate(self: *@This(), a: Fu32, b: Fu32, width: u5) Fu32 {
        const al = self.split(a.low, width);
        const ah = self.split(a.high, width);
        const bl = self.split(b.low, width);
        const bh = self.split(b.high, width);
        const low_xors = self.xor2(width, .{ al.low, ah.low }, .{ bl.low, bh.low });
        const high_width: u5 = @intCast(16 - width);
        const high_xors = self.xor2(
            high_width,
            .{ al.high, ah.high },
            .{ bl.high, bh.high },
        );
        const factor = M31.fromCanonical(@as(u32, 1) << high_width);
        return .{
            .low = low_xors[1].mulM31(factor).add(high_xors[0]),
            .high = low_xors[0].mulM31(factor).add(high_xors[1]),
        };
    }

    fn xorRotate16(self: *@This(), a: Fu32, b: Fu32) Fu32 {
        const al = self.split(a.low, 8);
        const ah = self.split(a.high, 8);
        const bl = self.split(b.low, 8);
        const bh = self.split(b.high, 8);
        const low_xors = self.xor2(8, .{ al.low, ah.low }, .{ bl.low, bh.low });
        const high_xors = self.xor2(8, .{ al.high, ah.high }, .{ bl.high, bh.high });
        const factor = M31.fromCanonical(1 << 8);
        return .{
            .low = high_xors[1].mulM31(factor).add(low_xors[1]),
            .high = high_xors[0].mulM31(factor).add(low_xors[0]),
        };
    }

    fn xor2(
        self: *@This(),
        width: u5,
        a: [2]QM31,
        b: [2]QM31,
    ) [2]QM31 {
        const result = [2]QM31{ self.next(), self.next() };
        const relation = self.elements.xorForWidth(width);
        for (0..2) |index| {
            self.entries[self.entry_index] = .{
                .multiplicity = QM31.one(),
                .denominator = relation.combineSecure(&.{
                    a[index],
                    b[index],
                    result[index],
                }),
            };
            self.entry_index += 1;
        }
        return result;
    }
};

fn appendFu32s(
    output: *[constants.N_ROUND_INPUT_FELTS]QM31,
    index: *usize,
    values: []const Fu32,
) void {
    for (values) |value| {
        output[index.*] = value.low;
        output[index.* + 1] = value.high;
        index.* += 2;
    }
}

test "exact Blake round witness satisfies all 64 arithmetic constraints" {
    const round_trace = @import("round_trace.zig");
    const NullObserver = struct {
        pub fn record(_: *@This(), _: u5, _: u32, _: u32, _: u32) void {}
    };
    var observer = NullObserver{};
    const trace = round_trace.generate(
        [_]u32{0x1234_5678} ** constants.STATE_SIZE,
        [_]u32{0x9abc_def0} ** constants.MESSAGE_SIZE,
        &observer,
    );
    var main: [geometry.ROUND_MAIN_COLUMNS]QM31 = undefined;
    for (&main, trace.row) |*out, value| {
        out.* = QM31.fromBase(M31.fromCanonical(value));
    }
    const relation = statement_mod.RelationElements{
        .z = QM31.fromU32Unchecked(101, 103, 107, 109),
        .alpha = QM31.fromU32Unchecked(2, 3, 5, 7),
    };
    const elements = statement_mod.AllElements{
        .blake = relation,
        .round = relation,
        .xor = [_]statement_mod.RelationElements{relation} ** geometry.XOR_TABLES.len,
    };
    const constraints = try algebraicConstraints(main, &elements);
    for (constraints) |constraint| try std.testing.expect(constraint.isZero());
}
