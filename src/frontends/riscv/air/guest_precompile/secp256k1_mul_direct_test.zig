const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const direct = @import("secp256k1_mul_direct.zig");
const field = @import("secp256k1_field.zig");

const challenge = QM31.fromU32Unchecked(13, 17, 19, 23);

const Sink = struct {
    count: usize = 0,
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.count += 1;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 multiplication AIR: honest base and scalar rows vanish" {
    for ([_]field.Modulus{ field.base_modulus, field.scalar_modulus }) |modulus| {
        const witness = try field.create(
            field.bytesFromInteger(modulus.integer() - 123_456_789),
            field.bytesFromInteger(modulus.integer() - 987_654_321),
            modulus,
        );
        const row = direct.rowFromWitness(&witness);
        var sink = Sink{};
        direct.evaluateGeneric(M31, &row, modulus, challenge, &sink);
        try std.testing.expectEqual(direct.constraint_count, sink.count);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expectEqual(direct.maximum_constraint_degree, sink.maximum_degree);
    }
}

test "secp256k1 multiplication AIR: polynomial and canonical mutations fail" {
    const witness = try field.create(
        field.bytesFromInteger(0x123456789abcdef),
        field.bytesFromInteger(0xfedcba987654321),
        field.base_modulus,
    );
    const honest = direct.rowFromWitness(&witness);

    const mutations = [_]usize{
        direct.Layout.lhs + 3,
        direct.Layout.rhs + 7,
        direct.Layout.result + 11,
        direct.Layout.quotient + 13,
        direct.Layout.carry_low + 17,
        direct.Layout.carry_high + 23,
        direct.Layout.canonical_sum + 5,
        direct.Layout.canonical_carry + 8,
    };
    for (mutations) |column| {
        var row = honest;
        row[column] = row[column].add(M31.one());
        var sink = Sink{};
        direct.evaluateGeneric(M31, &row, field.base_modulus, challenge, &sink);
        try std.testing.expect(sink.failures != 0);
    }

    var row = honest;
    row[direct.Layout.is_active] = M31.fromU64(2);
    var sink = Sink{};
    direct.evaluateGeneric(M31, &row, field.base_modulus, challenge, &sink);
    try std.testing.expect(sink.failures != 0);
}

test "secp256k1 multiplication AIR: QM31 point evaluation matches base row" {
    const witness = try field.create(
        field.bytesFromInteger(0xaaaabbbbccccddddeeeeffff),
        field.bytesFromInteger(0x111122223333444455556666),
        field.base_modulus,
    );
    const base_row = direct.rowFromWitness(&witness);
    var secure_row: [direct.Layout.main_columns]QM31 = undefined;
    for (&secure_row, base_row) |*out, value| out.* = QM31.fromBase(value);

    var base_sink = Sink{};
    direct.evaluateGeneric(M31, &base_row, field.base_modulus, challenge, &base_sink);
    var secure_sink = Sink{};
    direct.evaluateGeneric(QM31, &secure_row, field.base_modulus, challenge, &secure_sink);
    try std.testing.expectEqual(base_sink.count, secure_sink.count);
    try std.testing.expectEqual(base_sink.failures, secure_sink.failures);
}

test "secp256k1 multiplication AIR: every byte enters one exact range pair" {
    const witness = try field.create(
        field.bytesFromInteger(123),
        field.bytesFromInteger(456),
        field.base_modulus,
    );
    var row = direct.rowFromWitness(&witness);
    const pairs = direct.rangePairs(M31, &row);
    try std.testing.expectEqual(@as(usize, 142), pairs.len);
    for (pairs) |pair| {
        try std.testing.expect(pair[0].toU32() <= 255);
        try std.testing.expect(pair[1].toU32() <= 255);
    }

    row[direct.Layout.quotient + 9] = M31.fromU64(256);
    const forged = direct.rangePairs(M31, &row);
    var rejected = false;
    for (forged) |pair| {
        rejected = rejected or pair[0].toU32() > 255 or pair[1].toU32() > 255;
    }
    try std.testing.expect(rejected);
}
