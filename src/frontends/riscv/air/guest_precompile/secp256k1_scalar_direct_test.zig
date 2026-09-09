const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const ecdsa = @import("secp256k1_ecdsa.zig");
const fixture = @import("secp256k1_affine_test.zig").csp_input;
const direct = @import("secp256k1_scalar_direct.zig");
const relations_mod = @import("secp256k1_relations.zig");

const Sink = struct {
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 scalar AIR: complete CSP GLV schedule vanishes" {
    var tape = try cspTape();
    defer tape.deinit();
    const program = &tape.scalar_programs.items[0];
    try std.testing.expect(program.step_count > 0 and program.step_count <= 130);

    var previous: [direct.Layout.main_columns]M31 = @splat(M31.zero());
    for (0..program.step_count) |ordinal| {
        const row = try direct.rowFromStep(&tape, program, ordinal);
        const next = if (ordinal + 1 < program.step_count)
            try direct.rowFromStep(&tape, program, ordinal + 1)
        else
            [_]M31{M31.zero()} ** direct.Layout.main_columns;
        var sink = Sink{};
        direct.evaluateDirect(
            M31,
            &row,
            &previous,
            &next,
            M31.fromU64(@intFromBool(ordinal == 0)),
            M31.fromU64(@intFromBool(ordinal + 1 == program.step_count)),
            &sink,
        );
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);
        previous = row;
    }
}

test "secp256k1 scalar AIR: every schedule request cancels its exact authority" {
    var tape = try cspTape();
    defer tape.deinit();
    const program = &tape.scalar_programs.items[0];
    const relations = relations_mod.Relations.dummy();
    var previous: [direct.Layout.main_columns]M31 = @splat(M31.zero());
    for (0..program.step_count) |ordinal| {
        const step = &tape.scalar_steps.items[program.step_start + ordinal];
        const row = try direct.rowFromStep(&tape, program, ordinal);
        var sum = try pairSum(&direct.rowPairs(M31, &row, &previous, &relations));
        if (ordinal == 0) {
            for (tape.scalar_splits.items[program.split_start..][0..2]) |*split| {
                sum = sum.add(relations_mod.combineSplit(
                    M31,
                    relations.split,
                    relations_mod.splitTupleForRecord(split),
                ).inv() catch unreachable);
            }
            const root_point = relations_mod.encodePoint(program.point);
            for ([_]affine.TableKind{ .public_key, .public_key_endomorphism }) |kind| {
                const root = relations_mod.tableRootTuple(
                    M31,
                    M31.fromU64(@intFromEnum(kind)),
                    &root_point,
                );
                sum = sum.sub(relations_mod.combineTableRoot(
                    M31,
                    relations.table_root,
                    root,
                ).inv() catch unreachable);
            }
        }
        const tables = tape.tables.items[program.table_start..][0..direct.scalar_count];
        for (0..direct.scalar_count) |scalar_index| {
            const digit = step.digits[scalar_index];
            if (digit == 0) continue;
            const code = affine.signedTableIndex(digit);
            sum = sum.add(relations_mod.combineTable(
                M31,
                relations.table,
                relations_mod.tableTupleForEntry(
                    tables[scalar_index].kind,
                    code,
                    tables[scalar_index].entries[code],
                ),
            ).inv() catch unreachable);
        }
        for (step.point_record_indices, 0..) |record_index, transition| {
            if (transition != 0 and step.digits[transition - 1] == 0) continue;
            const point = &tape.points.items[record_index];
            sum = sum.add(relations_mod.combinePoint(
                M31,
                relations.point,
                relations_mod.pointTupleForRecord(point),
            ).inv() catch unreachable);
        }
        if (ordinal + 1 == program.step_count) {
            sum = sum.sub(relations_mod.combineProgram(
                M31,
                relations.program,
                relations_mod.programTupleForRecord(program),
            ).inv() catch unreachable);
        }
        try std.testing.expect(sum.isZero());
        previous = row;
    }
}

test "secp256k1 scalar AIR: digit recurrence and chain mutations reject" {
    var tape = try cspTape();
    defer tape.deinit();
    const program = &tape.scalar_programs.items[0];
    const row = try direct.rowFromStep(&tape, program, 0);
    const next = try direct.rowFromStep(&tape, program, 1);
    const previous: [direct.Layout.main_columns]M31 = @splat(M31.zero());

    var forged = row;
    var selected_code: usize = 0;
    for (0..direct.digit_count) |code| {
        if (row[direct.Layout.digitSelector(0, code)].isOne()) selected_code = code;
    }
    forged[direct.Layout.digitSelector(0, (selected_code + 1) % direct.digit_count)] = M31.one();
    var sink = Sink{};
    direct.evaluateDirect(M31, &forged, &previous, &next, M31.one(), M31.zero(), &sink);
    try std.testing.expect(sink.failures != 0);

    forged = row;
    forged[direct.Layout.state(1) + 7] =
        forged[direct.Layout.state(1) + 7].add(M31.one());
    sink = .{};
    direct.evaluateDirect(M31, &forged, &previous, &next, M31.one(), M31.zero(), &sink);
    try std.testing.expect(sink.failures != 0);

    var forged_previous = row;
    forged_previous[direct.Layout.afterAdd(3) + 1] = M31.one();
    const second = try direct.rowFromStep(&tape, program, 1);
    const third = try direct.rowFromStep(&tape, program, 2);
    sink = .{};
    direct.evaluateDirect(
        M31,
        &second,
        &forged_previous,
        &third,
        M31.zero(),
        M31.zero(),
        &sink,
    );
    try std.testing.expect(sink.failures != 0);
}

test "secp256k1 scalar AIR: private recurrence state is range-covered" {
    var tape = try cspTape();
    defer tape.deinit();
    const program = &tape.scalar_programs.items[0];
    var row = try direct.rowFromStep(&tape, program, 0);
    const pairs = direct.rangePairs(M31, &row);
    try std.testing.expectEqual(@as(usize, 32), pairs.len);
    row[direct.Layout.state_after + 7] = M31.fromU64(256);
    const forged = direct.rangePairs(M31, &row);
    var rejected = false;
    for (forged) |pair| rejected = rejected or
        pair[0].toU32() > 255 or pair[1].toU32() > 255;
    try std.testing.expect(rejected);
}

fn cspTape() !affine.Tape {
    var tape = affine.Tape.init(std.testing.allocator);
    errdefer tape.deinit();
    if (!try ecdsa.verify(
        &tape,
        fixture[0..32].*,
        fixture[32..97].*,
        fixture[97..129].*,
        fixture[129..161].*,
    )) return error.InvalidFixture;
    return tape;
}

fn pairSum(pairs: *const [direct.batch_count]@import("../logup.zig").RowPair) !QM31 {
    var result = QM31.zero();
    for (pairs) |pair| {
        result = result.add(pair.n1.mul(try pair.d1.inv()));
        result = result.add(pair.n2.mul(try pair.d2.inv()));
    }
    return result;
}
