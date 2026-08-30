const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const field = @import("secp256k1_field.zig");

const challenges = [_]QM31{
    QM31.fromU32Unchecked(3, 5, 7, 11),
    QM31.fromU32Unchecked(257, 1, 0, 1),
    QM31.fromU32Unchecked(65_537, 17, 19, 23),
};

test "secp256k1 field: modulus identities and boundary products are exact" {
    try std.testing.expectEqual(
        @as(u256, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f),
        field.base_modulus.integer(),
    );
    try std.testing.expectEqual(
        @as(u256, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141),
        field.scalar_modulus.integer(),
    );

    for ([_]field.Modulus{ field.base_modulus, field.scalar_modulus }) |modulus| {
        const zero = field.bytesFromInteger(0);
        const one = field.bytesFromInteger(1);
        const maximum = field.bytesFromInteger(modulus.integer() - 1);

        var witness = try field.create(zero, maximum, modulus);
        try expectValid(&witness, modulus);
        try std.testing.expectEqual(@as(u256, 0), integer(witness.result));

        witness = try field.create(one, maximum, modulus);
        try expectValid(&witness, modulus);
        try std.testing.expectEqual(modulus.integer() - 1, integer(witness.result));

        witness = try field.create(maximum, maximum, modulus);
        try expectValid(&witness, modulus);
        try std.testing.expectEqual(@as(u256, 1), integer(witness.result));
        try std.testing.expectEqual(modulus.integer() - 2, integer(witness.quotient));
    }
}

test "secp256k1 field: randomized corpus agrees with u512 arithmetic" {
    var generator = std.Random.DefaultPrng.init(0x5ec0_2561_5ec0_2561);
    const random = generator.random();
    for ([_]field.Modulus{ field.base_modulus, field.scalar_modulus }) |modulus| {
        const modulus_wide = @as(u512, modulus.integer());
        for (0..256) |_| {
            const lhs_value = random.int(u256) % modulus.integer();
            const rhs_value = random.int(u256) % modulus.integer();
            const witness = try field.create(
                field.bytesFromInteger(lhs_value),
                field.bytesFromInteger(rhs_value),
                modulus,
            );
            try expectValid(&witness, modulus);
            const product = @as(u512, lhs_value) * @as(u512, rhs_value);
            try std.testing.expectEqual(
                @as(u256, @intCast(product % modulus_wide)),
                integer(witness.result),
            );
            try std.testing.expectEqual(
                @as(u256, @intCast(product / modulus_wide)),
                integer(witness.quotient),
            );
        }
    }
}

test "secp256k1 field: every committed witness family is mutation-visible" {
    const lhs = field.bytesFromInteger(0x123456789abcdef0123456789abcdef0);
    const rhs = field.bytesFromInteger(0xfedcba9876543210fedcba987654321);
    const honest = try field.create(lhs, rhs, field.base_modulus);
    try expectValid(&honest, field.base_modulus);

    var mutated = honest;
    mutated.lhs[3] +%= 1;
    try expectPolynomialFailure(&mutated);
    mutated = honest;
    mutated.rhs[7] +%= 1;
    try expectPolynomialFailure(&mutated);
    mutated = honest;
    mutated.result[11] +%= 1;
    try expectPolynomialFailure(&mutated);
    mutated = honest;
    mutated.quotient[13] +%= 1;
    try expectPolynomialFailure(&mutated);
    mutated = honest;
    mutated.carry_low[17] +%= 1;
    try expectPolynomialFailure(&mutated);
    mutated = honest;
    mutated.carry_high[23] +%= 1;
    try expectPolynomialFailure(&mutated);

    mutated = honest;
    mutated.canonical_sum[0] +%= 1;
    try std.testing.expectError(
        error.InvalidCanonicalWitness,
        mutated.validateAt(field.base_modulus, challenges[0]),
    );
    mutated = honest;
    mutated.canonical_carry[1] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalWitness,
        mutated.validateAt(field.base_modulus, challenges[0]),
    );
}

test "secp256k1 field: noncanonical operands fail before witness publication" {
    const one = field.bytesFromInteger(1);
    try std.testing.expectError(
        error.NonCanonicalOperand,
        field.create(field.base_modulus.bytes, one, field.base_modulus),
    );
    try std.testing.expectError(
        error.NonCanonicalOperand,
        field.create(one, field.scalar_modulus.bytes, field.scalar_modulus),
    );

    const zero_modulus = field.Modulus.init(@splat(0));
    try std.testing.expectError(
        error.ZeroModulus,
        field.create(@splat(0), @splat(0), zero_modulus),
    );
}

fn expectValid(witness: *const field.Witness, modulus: field.Modulus) !void {
    try witness.validateExact(modulus);
    for (challenges) |challenge| try witness.validateAt(modulus, challenge);
}

fn expectPolynomialFailure(witness: *const field.Witness) !void {
    var detected = false;
    for (challenges) |challenge| {
        detected = detected or !witness.residualAt(field.base_modulus, challenge).isZero();
    }
    try std.testing.expect(detected);
}

fn integer(bytes: [field.limb_count]u8) u256 {
    return std.mem.readInt(u256, &bytes, .little);
}
