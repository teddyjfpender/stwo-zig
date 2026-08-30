//! Compact non-native secp256k1 modular-multiplication authority.
//!
//! Values use 32 radix-256 limbs so guest-memory bytes can enter the eventual
//! component without repacking.  For `lhs * rhs = quotient * modulus + result`,
//! the committed carry polynomial makes the coefficient identity
//!
//!   A(X)B(X) - R(X) - Q(X)P(X) = (X - 256)C(X)
//!
//! hold over the integers.  Evaluating that degree-62 identity at a QM31
//! challenge drawn after the main commitment replaces 63 coefficient
//! constraints without weakening byte or carry range authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const limb_count: usize = 32;
pub const product_coefficient_count: usize = 2 * limb_count - 1;
pub const carry_count: usize = product_coefficient_count - 1;
pub const radix: i64 = 256;
pub const carry_offset: i64 = 1 << 15;
pub const maximum_polynomial_degree: u8 = 62;

pub const Error = error{
    ZeroModulus,
    NonCanonicalOperand,
    QuotientOverflow,
    NonIntegralCarry,
    CarryOutOfRange,
    InvalidTerminalCarry,
    InvalidCanonicalWitness,
    PolynomialIdentityMismatch,
};

pub const Modulus = struct {
    bytes: [limb_count]u8,
    complement: [limb_count]u8,

    pub fn init(bytes: [limb_count]u8) Modulus {
        var complement: [limb_count]u8 = undefined;
        var carry: u16 = 1;
        for (&complement, bytes) |*out, byte| {
            const value = @as(u16, ~byte) + carry;
            out.* = @truncate(value);
            carry = value >> 8;
        }
        return .{ .bytes = bytes, .complement = complement };
    }

    pub fn integer(self: Modulus) u256 {
        return std.mem.readInt(u256, &self.bytes, .little);
    }
};

/// secp256k1 base field `2^256 - 2^32 - 977`, in little-endian bytes.
pub const base_modulus = Modulus.init(.{
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
});

/// secp256k1 subgroup order, in little-endian bytes.
pub const scalar_modulus = Modulus.init(.{
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
    0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
});

pub const Witness = struct {
    lhs: [limb_count]u8,
    rhs: [limb_count]u8,
    result: [limb_count]u8,
    quotient: [limb_count]u8,
    carry_low: [carry_count]u8,
    carry_high: [carry_count]u8,
    canonical_sum: [limb_count]u8,
    canonical_carry: [limb_count + 1]u8,

    pub fn carry(self: *const Witness, index: usize) i64 {
        std.debug.assert(index < carry_count);
        const encoded = @as(u16, self.carry_low[index]) |
            (@as(u16, self.carry_high[index]) << 8);
        return @as(i64, encoded) - carry_offset;
    }

    /// Exact integer oracle used by witness generation and adversarial tests.
    /// Production AIR uses `residualAt` plus byte/carry/canonical lookups.
    pub fn validateExact(self: *const Witness, modulus: Modulus) Error!void {
        try validateCanonicalOperands(self, modulus);
        var previous: i64 = 0;
        for (0..carry_count) |index| {
            const current = self.carry(index);
            const expected = if (index == 0)
                -radix * current
            else
                previous - radix * current;
            if (coefficient(self, modulus, index) != expected)
                return error.NonIntegralCarry;
            previous = current;
        }
        if (coefficient(self, modulus, product_coefficient_count - 1) != previous)
            return error.InvalidTerminalCarry;
        try validateCanonicalResult(self, modulus);
    }

    /// Secure randomized identity used by the AIR after main commitment.
    pub fn residualAt(self: *const Witness, modulus: Modulus, challenge: QM31) QM31 {
        const a = evaluateBytes(self.lhs, challenge);
        const b = evaluateBytes(self.rhs, challenge);
        const r = evaluateBytes(self.result, challenge);
        const q = evaluateBytes(self.quotient, challenge);
        const p = evaluateBytes(modulus.bytes, challenge);
        const c = evaluateCarries(self, challenge);
        const radix_at = QM31.fromBase(M31.fromU64(@intCast(radix)));
        return a.mul(b)
            .sub(r)
            .sub(q.mul(p))
            .sub(challenge.sub(radix_at).mul(c));
    }

    pub fn validateAt(
        self: *const Witness,
        modulus: Modulus,
        challenge: QM31,
    ) Error!void {
        try validateCanonicalOperands(self, modulus);
        try validateCanonicalResult(self, modulus);
        if (!self.residualAt(modulus, challenge).isZero())
            return error.PolynomialIdentityMismatch;
    }
};

pub fn create(
    lhs: [limb_count]u8,
    rhs: [limb_count]u8,
    modulus: Modulus,
) Error!Witness {
    const modulus_value = modulus.integer();
    if (modulus_value == 0) return error.ZeroModulus;
    const lhs_value = std.mem.readInt(u256, &lhs, .little);
    const rhs_value = std.mem.readInt(u256, &rhs, .little);
    if (lhs_value >= modulus_value or rhs_value >= modulus_value)
        return error.NonCanonicalOperand;

    const product = @as(u512, lhs_value) * @as(u512, rhs_value);
    const modulus_wide = @as(u512, modulus_value);
    const quotient_wide = product / modulus_wide;
    if (quotient_wide > std.math.maxInt(u256)) return error.QuotientOverflow;
    const result_wide = product - quotient_wide * modulus_wide;

    var witness: Witness = undefined;
    witness.lhs = lhs;
    witness.rhs = rhs;
    std.mem.writeInt(u256, &witness.result, @intCast(result_wide), .little);
    std.mem.writeInt(u256, &witness.quotient, @intCast(quotient_wide), .little);

    var previous: i64 = 0;
    for (0..carry_count) |index| {
        const numerator = previous - coefficient(&witness, modulus, index);
        if (@mod(numerator, radix) != 0) return error.NonIntegralCarry;
        const current = @divExact(numerator, radix);
        try encodeCarry(&witness, index, current);
        previous = current;
    }
    if (coefficient(&witness, modulus, product_coefficient_count - 1) != previous)
        return error.InvalidTerminalCarry;

    witness.canonical_carry[0] = 0;
    var canonical_carry: u16 = 0;
    for (0..limb_count) |index| {
        const sum = @as(u16, witness.result[index]) +
            @as(u16, modulus.complement[index]) + canonical_carry;
        witness.canonical_sum[index] = @truncate(sum);
        canonical_carry = sum >> 8;
        witness.canonical_carry[index + 1] = @intCast(canonical_carry);
    }
    if (canonical_carry != 0) return error.NonCanonicalOperand;

    try witness.validateExact(modulus);
    return witness;
}

pub fn bytesFromInteger(value: u256) [limb_count]u8 {
    var result: [limb_count]u8 = undefined;
    std.mem.writeInt(u256, &result, value, .little);
    return result;
}

fn validateCanonicalOperands(self: *const Witness, modulus: Modulus) Error!void {
    if (!lessThan(self.lhs, modulus.bytes) or
        !lessThan(self.rhs, modulus.bytes) or
        !lessThan(self.result, modulus.bytes))
    {
        return error.NonCanonicalOperand;
    }
}

fn validateCanonicalResult(self: *const Witness, modulus: Modulus) Error!void {
    if (self.canonical_carry[0] != 0 or self.canonical_carry[limb_count] != 0)
        return error.InvalidCanonicalWitness;
    var carry: u16 = 0;
    for (0..limb_count) |index| {
        if (self.canonical_carry[index] > 1 or
            self.canonical_carry[index + 1] > 1)
        {
            return error.InvalidCanonicalWitness;
        }
        if (self.canonical_carry[index] != carry)
            return error.InvalidCanonicalWitness;
        const sum = @as(u16, self.result[index]) +
            @as(u16, modulus.complement[index]) + carry;
        if (self.canonical_sum[index] != @as(u8, @truncate(sum)) or
            self.canonical_carry[index + 1] != @as(u8, @intCast(sum >> 8)))
        {
            return error.InvalidCanonicalWitness;
        }
        carry = sum >> 8;
    }
    if (carry != 0) return error.InvalidCanonicalWitness;
}

fn encodeCarry(self: *Witness, index: usize, value: i64) Error!void {
    if (value < -carry_offset or value >= carry_offset)
        return error.CarryOutOfRange;
    const encoded: u16 = @intCast(value + carry_offset);
    self.carry_low[index] = @truncate(encoded);
    self.carry_high[index] = @truncate(encoded >> 8);
}

fn coefficient(self: *const Witness, modulus: Modulus, index: usize) i64 {
    std.debug.assert(index < product_coefficient_count);
    var value: i64 = 0;
    const first = if (index >= limb_count - 1) index - (limb_count - 1) else 0;
    const last = @min(index, limb_count - 1);
    var lhs_index = first;
    while (lhs_index <= last) : (lhs_index += 1) {
        const rhs_index = index - lhs_index;
        value += @as(i64, self.lhs[lhs_index]) * self.rhs[rhs_index];
        value -= @as(i64, self.quotient[lhs_index]) * modulus.bytes[rhs_index];
    }
    if (index < limb_count) value -= self.result[index];
    return value;
}

fn evaluateBytes(bytes: [limb_count]u8, challenge: QM31) QM31 {
    var result = QM31.zero();
    var index = limb_count;
    while (index != 0) {
        index -= 1;
        result = result.mul(challenge).addM31(M31.fromU64(bytes[index]));
    }
    return result;
}

fn evaluateCarries(self: *const Witness, challenge: QM31) QM31 {
    var result = QM31.zero();
    var index = carry_count;
    while (index != 0) {
        index -= 1;
        result = result.mul(challenge).add(QM31.fromBase(signedM31(self.carry(index))));
    }
    return result;
}

fn signedM31(value: i64) M31 {
    if (value >= 0) return M31.fromU64(@intCast(value));
    return M31.fromU64(@intCast(-value)).neg();
}

fn lessThan(lhs: [limb_count]u8, rhs: [limb_count]u8) bool {
    var index = limb_count;
    while (index != 0) {
        index -= 1;
        if (lhs[index] < rhs[index]) return true;
        if (lhs[index] > rhs[index]) return false;
    }
    return false;
}
