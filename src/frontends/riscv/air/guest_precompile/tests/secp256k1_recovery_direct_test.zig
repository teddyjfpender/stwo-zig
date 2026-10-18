const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("../secp256k1_affine.zig");
const direct = @import("../secp256k1_recovery_direct.zig");
const fixture = @import("secp256k1_affine_test.zig").csp_input;
const recovery = @import("../secp256k1_recovery.zig");
const relations_mod = @import("../secp256k1_relations.zig");
const scalar_direct = @import("../secp256k1_scalar_direct.zig");

const Sink = struct {
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 recovery AIR: parity-bound CSP transaction vanishes" {
    var tape = try recoveryTape();
    defer tape.deinit();
    const record = &tape.recoveries.items[0];
    const row = try direct.rowFromRecord(&tape, record);
    var sink = Sink{};
    direct.evaluateDirect(M31, &row, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.failures);
    try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);
    try std.testing.expectEqual(record.recovery_id, record.recovery_point.y[0] & 1);
    try std.testing.expectEqual(@as(usize, 81), direct.rangePairs(M31, &row).len);
}

test "secp256k1 recovery AIR: high-level row closes exact arithmetic tape" {
    var tape = try recoveryTape();
    defer tape.deinit();
    const record = &tape.recoveries.items[0];
    const row = try direct.rowFromRecord(&tape, record);
    const relations = relations_mod.Relations.dummy();
    var sum = try pairSum(&direct.rowPairs(M31, &row, &relations));
    for (tape.products.items[record.product_start..][0..7]) |*product| {
        sum = sum.add(try relations_mod.combineProduct(
            M31,
            relations.product,
            relations_mod.productTupleForRecord(product),
        ).inv());
    }
    for (tape.linears.items[record.linear_start..][0..direct.linear_record_count]) |*linear| {
        sum = sum.add(try relations_mod.combineLinear(
            M31,
            relations.linear,
            relations_mod.linearTupleForRecord(linear),
        ).inv());
    }
    const program = &tape.scalar_programs.items[record.program_index];
    sum = sum.add(try relations_mod.combineProgram(
        M31,
        relations.program,
        relations_mod.programTupleForRecord(program),
    ).inv());
    sum = sum.sub(try relations_mod.combineRecovery(
        M31,
        relations.recovery,
        relations_mod.recoveryTupleForRecord(record),
    ).inv());
    try std.testing.expect(sum.isZero());
}

test "secp256k1 recovery AIR: recid r and output mutations fail closed" {
    var tape = try recoveryTape();
    defer tape.deinit();
    const row = try direct.rowFromRecord(&tape, &tape.recoveries.items[0]);
    const relations = relations_mod.Relations.dummy();
    const baseline = try pairSum(&direct.rowPairs(M31, &row, &relations));

    var forged = row;
    forged[direct.Layout.recovery_id] = M31.one().sub(
        forged[direct.Layout.recovery_id],
    );
    var sink = Sink{};
    direct.evaluateDirect(M31, &forged, &sink);
    try std.testing.expect(sink.failures != 0);
    try std.testing.expect(!baseline.eql(try pairSum(&direct.rowPairs(
        M31,
        &forged,
        &relations,
    ))));

    forged = row;
    forged[direct.Layout.recovery_point + 1] =
        forged[direct.Layout.recovery_point + 1].add(M31.one());
    sink = .{};
    direct.evaluateDirect(M31, &forged, &sink);
    try std.testing.expect(sink.failures != 0);

    forged = row;
    forged[direct.Layout.public_key + 1 + 7] =
        forged[direct.Layout.public_key + 1 + 7].add(M31.one());
    try std.testing.expect(!baseline.eql(try pairSum(&direct.rowPairs(
        M31,
        &forged,
        &relations,
    ))));
}

test "secp256k1 recovery AIR: r and s are bound below the group order" {
    const field = @import("../secp256k1_field.zig");
    const linear_direct = @import("../secp256k1_linear_direct.zig");
    var tape = try recoveryTape();
    defer tape.deinit();
    const record = &tape.recoveries.items[0];
    const row = try direct.rowFromRecord(&tape, record);
    const relations = relations_mod.Relations.dummy();
    const order = field.scalar_modulus.integer();

    // The honest row requests `reduce_once(r, n) == r` and the same for `s`.
    const linears = tape.linears.items[record.linear_start..][0..direct.linear_record_count];
    try std.testing.expectEqual(affine.LinearKind.reduce_once, linears[2].kind);
    try std.testing.expectEqual(affine.LinearKind.reduce_once, linears[3].kind);
    try std.testing.expectEqualSlices(u8, &record.r, &linears[2].lhs);
    try std.testing.expectEqualSlices(u8, &record.r, &linears[2].result);
    try std.testing.expectEqualSlices(u8, &record.s, &linears[3].lhs);
    try std.testing.expectEqualSlices(u8, &record.s, &linears[3].result);
    const honest = try pairSum(&direct.rowPairs(M31, &row, &relations));

    // A non-canonical representative `v in [n, 2^256)` of a valid scalar class
    // satisfies every direct constraint and every modular product request (a
    // product row does not require canonical operands); only the canonical
    // reduction request distinguishes it, and no linear row can serve that
    // request because the linear AIR forces its result below the modulus.
    const representative = field.bytesFromInteger(order + 7);
    inline for (.{ direct.Layout.r, direct.Layout.s }) |offset| {
        var forged = row;
        for (representative, 0..) |byte, index| forged[offset + index] = M31.fromU64(byte);
        if (offset == direct.Layout.r) {
            for (representative, 0..) |byte, index| {
                forged[direct.Layout.recovery_point + 1 + index] = M31.fromU64(byte);
            }
        }
        var sink = Sink{};
        direct.evaluateDirect(M31, &forged, &sink);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expect(!honest.eql(try pairSum(&direct.rowPairs(M31, &forged, &relations))));
    }
    const non_canonical = affine.LinearRecord{
        .kind = .reduce_once,
        .modulus = .scalar,
        .lhs = representative,
        .rhs = field.scalar_modulus.bytes,
        .result = representative,
    };
    try std.testing.expectError(
        error.NonCanonicalOperand,
        linear_direct.rowFromRecord(&non_canonical),
    );

    // The witness generator refuses out-of-range scalars outright.
    var big_s: [32]u8 = undefined;
    std.mem.writeInt(u256, &big_s, order, .big);
    var scratch = affine.Tape.init(std.testing.allocator);
    defer scratch.deinit();
    try std.testing.expectError(error.InvalidScalar, recovery.recover(
        &scratch,
        fixture[0..32].*,
        fixture[97..129].*,
        big_s,
        0,
        fixture[33..97].*,
    ));
}

test "secp256k1 recovery witness: invalid requests are fail atomic" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const before = lengths(&tape);
    var wrong_key: [64]u8 = fixture[33..97].*;
    wrong_key[0] ^= 1;
    try std.testing.expectError(
        error.RecoveredPublicKeyMismatch,
        recovery.recover(
            &tape,
            fixture[0..32].*,
            fixture[97..129].*,
            fixture[129..161].*,
            0,
            wrong_key,
        ),
    );
    try std.testing.expectEqualDeep(before, lengths(&tape));
    try std.testing.expectError(
        error.InvalidRecoveryId,
        recovery.recover(
            &tape,
            fixture[0..32].*,
            fixture[97..129].*,
            fixture[129..161].*,
            2,
            fixture[33..97].*,
        ),
    );
    try std.testing.expectEqualDeep(before, lengths(&tape));
}

test "secp256k1 recovery witness: a recovery whose add slot meets its own table entry proves" {
    // Submitter-chosen input with R = G, s = r and z = n - r, so
    // u1 = -z * r^-1 = 1 and u2 = s * r^-1 = 1: the program is 1*G + 1*G and
    // the point stream's add slot sees `accumulator == selected == G`. Before
    // `add_equal` this recovery was computed correctly by the tape but could
    // not be materialised (`InvalidTransition`), a per-request prover DoS.
    const field = @import("../secp256k1_field.zig");
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const generator = affine.basePoint();
    const r_big_endian = reverse(generator.x);
    const order = field.scalar_modulus.integer();
    try std.testing.expect(integer(generator.x) < order);
    const digest_big_endian = reverse(field.bytesFromInteger(order - integer(generator.x)));
    const twice = std.crypto.ecc.Secp256k1.basePoint.dbl().toUncompressedSec1();
    const recovery_id: u32 = generator.y[0] & 1;

    try recovery.recover(
        &tape,
        digest_big_endian,
        r_big_endian,
        r_big_endian,
        recovery_id,
        twice[1..65].*,
    );
    try std.testing.expectEqual(@as(usize, 1), tape.recoveries.items.len);
    const record = &tape.recoveries.items[0];
    try std.testing.expectEqual(@as(u256, 1), integer(record.generator_scalar));
    try std.testing.expectEqual(@as(u256, 1), integer(record.recovery_point_scalar));
    try std.testing.expect(affine.Point.eql(record.recovery_point, generator));

    const program = &tape.scalar_programs.items[record.program_index];
    var equal_slots: usize = 0;
    var previous: [scalar_direct.Layout.main_columns]M31 = @splat(M31.zero());
    for (0..program.step_count) |ordinal| {
        const step = &tape.scalar_steps.items[program.step_start + ordinal];
        for (1..1 + scalar_direct.scalar_count) |slot| {
            if (step.digits[slot - 1] == 0) continue;
            const point = &tape.points.items[step.point_record_indices[slot]];
            if (point.kind == .add_equal) {
                equal_slots += 1;
                try std.testing.expect(affine.Point.eql(point.rhs, step.selected[slot - 1]));
            }
        }
        const row = try scalar_direct.rowFromStep(&tape, program, ordinal);
        const next = if (ordinal + 1 < program.step_count)
            try scalar_direct.rowFromStep(&tape, program, ordinal + 1)
        else
            [_]M31{M31.zero()} ** scalar_direct.Layout.main_columns;
        var sink = Sink{};
        scalar_direct.evaluateDirect(
            M31,
            &row,
            &previous,
            &next,
            M31.fromU64(@intFromBool(ordinal == 0)),
            M31.fromU64(@intFromBool(ordinal + 1 == program.step_count)),
            &sink,
        );
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        previous = row;
    }
    try std.testing.expectEqual(@as(usize, 1), equal_slots);

    const row = try direct.rowFromRecord(&tape, record);
    var sink = Sink{};
    direct.evaluateDirect(M31, &row, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.failures);
}

fn reverse(input: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (input, 0..) |byte, index| result[input.len - 1 - index] = byte;
    return result;
}

fn integer(value: affine.Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}

fn recoveryTape() !affine.Tape {
    var tape = affine.Tape.init(std.testing.allocator);
    errdefer tape.deinit();
    for (0..2) |recovery_id| {
        recovery.recover(
            &tape,
            fixture[0..32].*,
            fixture[97..129].*,
            fixture[129..161].*,
            @intCast(recovery_id),
            fixture[33..97].*,
        ) catch |err| switch (err) {
            error.RecoveredPublicKeyMismatch => continue,
            else => return err,
        };
        return tape;
    }
    return error.InvalidFixture;
}

fn pairSum(pairs: *const [direct.batch_count]@import("../../logup.zig").RowPair) !QM31 {
    var result = QM31.zero();
    for (pairs) |pair| {
        result = result.add(pair.n1.mul(try pair.d1.inv()));
        result = result.add(pair.n2.mul(try pair.d2.inv()));
    }
    return result;
}

fn lengths(tape: *const affine.Tape) [9]usize {
    return .{
        tape.products.items.len,
        tape.linears.items.len,
        tape.points.items.len,
        tape.scalar_splits.items.len,
        tape.tables.items.len,
        tape.scalar_steps.items.len,
        tape.scalar_programs.items.len,
        tape.ecdsa.items.len,
        tape.recoveries.items.len,
    };
}
