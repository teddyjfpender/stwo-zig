//! Canonical Cairo interaction-trace checkpoint hashing.
//!
//! These hashes are diagnostic evidence only. Their fixed lookup elements are
//! deliberately independent of the Fiat-Shamir proof transcript.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Digest = [32]u8;
pub const SecureLimbs = [4]u32;
pub const alpha_power_count = 128;
pub const initial_accumulator = [_]u8{0} ** 32;

pub const challenge_domain = "STWO_CAIRO_INTERACTION_DIAGNOSTIC_CHALLENGE_V1\x00";
pub const lookup_elements_domain = "STWO_CAIRO_INTERACTION_LOOKUP_ELEMENTS_V1\x00";
pub const column_domain = "STWO_CAIRO_INTERACTION_COLUMN_V1\x00";
pub const accumulator_domain = "STWO_CAIRO_INTERACTION_ACCUMULATOR_V1\x00";

pub const diagnostic_z: SecureLimbs = .{ 2059688338, 2092506771, 453015876, 1425491019 };
pub const diagnostic_alpha: SecureLimbs = .{ 2020915545, 1141263798, 2012552380, 612327232 };

pub const Column = struct {
    ordinal: u32,
    row_count: u64,
    sha256: Digest,
};

pub const Component = struct {
    ordinal: u32,
    label: []const u8,
    claimed_sum_m31: SecureLimbs,
    columns: []const Column,
    accumulator: Digest,
};

pub const Error = error{
    EmptyLabel,
    LabelTooLong,
    EmptyComponent,
    InvalidAlphaPowerCount,
    NonCanonicalM31,
    RowCountOverflow,
};

pub fn validateLimbs(limbs: SecureLimbs) Error!void {
    for (limbs) |limb| {
        if (limb >= m31.Modulus) return Error.NonCanonicalM31;
    }
}

pub fn deriveAlphaPowers() [alpha_power_count]SecureLimbs {
    var powers: [alpha_power_count]SecureLimbs = undefined;
    const alpha = QM31.fromU32Unchecked(
        diagnostic_alpha[0],
        diagnostic_alpha[1],
        diagnostic_alpha[2],
        diagnostic_alpha[3],
    );
    var power = QM31.one();
    for (&powers) |*limbs| {
        const values = power.toM31Array();
        limbs.* = .{ values[0].v, values[1].v, values[2].v, values[3].v };
        power = power.mul(alpha);
    }
    return powers;
}

pub fn digestLookupElements(
    z_m31: SecureLimbs,
    alpha_powers_m31: []const SecureLimbs,
) Error!Digest {
    try validateLimbs(z_m31);
    if (alpha_powers_m31.len != alpha_power_count) return Error.InvalidAlphaPowerCount;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(lookup_elements_domain);
    for (z_m31) |limb| updateInt(&hasher, u32, limb);
    updateInt(&hasher, u32, alpha_power_count);
    for (alpha_powers_m31, 0..) |power, ordinal| {
        try validateLimbs(power);
        updateInt(&hasher, u32, @intCast(ordinal));
        for (power) |limb| updateInt(&hasher, u32, limb);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

/// Hashes one raw interaction base column in logical row order.
pub fn digestColumn(
    component_ordinal: u32,
    label: []const u8,
    column_ordinal: u32,
    values: []const u32,
) Error!Digest {
    try validateLabel(label);
    const row_count = std.math.cast(u64, values.len) orelse return Error.RowCountOverflow;
    var hasher = initColumnHasher(component_ordinal, label, column_ordinal, row_count);
    for (values) |value| {
        if (value >= m31.Modulus) return Error.NonCanonicalM31;
        updateInt(&hasher, u32, value);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

/// Hashes one coordinate of a secure interaction column without allocating a
/// second base-field column.
pub fn digestSecureCoordinate(
    component_ordinal: u32,
    label: []const u8,
    column_ordinal: u32,
    values: []const QM31,
    coordinate: u2,
) Error!Digest {
    try validateLabel(label);
    const row_count = std.math.cast(u64, values.len) orelse return Error.RowCountOverflow;
    var hasher = initColumnHasher(component_ordinal, label, column_ordinal, row_count);
    for (values) |value| {
        const limbs = value.toM31Array();
        updateInt(&hasher, u32, limbs[coordinate].v);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

pub fn extendAccumulator(
    previous: Digest,
    lookup_elements_digest: Digest,
    component_ordinal: u32,
    label: []const u8,
    claimed_sum_m31: SecureLimbs,
    columns: []const Column,
) Error!Digest {
    try validateLabel(label);
    try validateLimbs(claimed_sum_m31);
    if (columns.len == 0) return Error.EmptyComponent;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(accumulator_domain);
    hasher.update(&previous);
    hasher.update(&lookup_elements_digest);
    updateInt(&hasher, u32, component_ordinal);
    updateInt(&hasher, u32, @intCast(label.len));
    hasher.update(label);
    for (claimed_sum_m31) |limb| updateInt(&hasher, u32, limb);
    updateInt(&hasher, u32, @intCast(columns.len));
    for (columns) |column| {
        updateInt(&hasher, u32, column.ordinal);
        updateInt(&hasher, u64, column.row_count);
        hasher.update(&column.sha256);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

fn initColumnHasher(
    component_ordinal: u32,
    label: []const u8,
    column_ordinal: u32,
    row_count: u64,
) std.crypto.hash.sha2.Sha256 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(column_domain);
    updateInt(&hasher, u32, component_ordinal);
    updateInt(&hasher, u32, @intCast(label.len));
    hasher.update(label);
    updateInt(&hasher, u32, column_ordinal);
    updateInt(&hasher, u64, row_count);
    return hasher;
}

fn validateLabel(label: []const u8) Error!void {
    if (label.len == 0) return Error.EmptyLabel;
    if (label.len > std.math.maxInt(u32)) return Error.LabelTooLong;
}

fn updateInt(hasher: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hasher.update(&bytes);
}

test "interaction checkpoint derives the pinned alpha powers and lookup digest" {
    const powers = deriveAlphaPowers();
    try std.testing.expectEqual([_]u32{ 1, 0, 0, 0 }, powers[0]);
    try std.testing.expectEqual(diagnostic_alpha, powers[1]);
    const digest = try digestLookupElements(diagnostic_z, &powers);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xc7, 0x48, 0x85, 0xea, 0xf1, 0xa1, 0x99, 0x05,
        0x93, 0x85, 0x59, 0x49, 0x6c, 0x6f, 0xa7, 0x3f,
        0xf2, 0x17, 0x76, 0xab, 0xc2, 0xc5, 0xbc, 0x57,
        0x83, 0x07, 0xc1, 0xc7, 0xf4, 0xd7, 0xe3, 0x19,
    }, &digest);
}

test "interaction checkpoint rejects non-canonical M31 limbs" {
    var powers = deriveAlphaPowers();
    powers[17][2] = m31.Modulus;
    try std.testing.expectError(
        Error.NonCanonicalM31,
        digestLookupElements(diagnostic_z, &powers),
    );
}

test "interaction checkpoint hashes secure coordinates as base columns" {
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    };
    try std.testing.expectEqual(
        try digestColumn(2, "add_opcode", 7, &.{ 3, 7 }),
        try digestSecureCoordinate(2, "add_opcode", 7, &values, 2),
    );
}
