const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const direct = @import("secp256k1_recovery_direct.zig");
const fixture = @import("secp256k1_affine_test.zig").csp_input;
const recovery = @import("secp256k1_recovery.zig");
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
    for (tape.linears.items[record.linear_start..][0..3]) |*linear| {
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

fn pairSum(pairs: *const [direct.batch_count]@import("../logup.zig").RowPair) !QM31 {
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
