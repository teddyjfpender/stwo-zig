//! Experimental, uniform-domain paired FRI input for degree-corrected openings.
//!
//! This is an arithmetic/transcript building block, not an admitted PCS proof
//! mode. Callers must authenticate each original column and derive each
//! two-point quotient from that same column and its claimed OOD value. The
//! multi-domain folding insertion and proof envelope are not implemented here.

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const VERSION: u32 = 1;
const TRANSCRIPT_TAG: u64 = 0x5333_3150_4149_5231; // "S31PAIR1"

pub const Shape = struct {
    log_domain_size: u32,
    log_degree_bound: u32,
    /// Number of (original, quotient) pairs in one equal-height batch.
    original_column_count: u32,

    pub fn validate(self: Shape) !void {
        if (self.log_domain_size < 2 or self.log_domain_size > 30 or
            self.log_degree_bound >= self.log_domain_size or
            self.original_column_count == 0 or
            self.original_column_count > std.math.maxInt(u32) / 2)
        {
            return error.InvalidPairedShape;
        }
    }
};

/// Protocol 3, Eq. 66 uses one lambda for every word of an extended batch.
/// The exact native transcript schedule still needs theorem refinement.
pub const Challenges = struct {
    batch: QM31,
};

/// Bind the experimental mode and uniform degree geometry before drawing one
/// batch challenge. Call only after source commitments and OOD claims are mixed.
/// Legacy PCS transcripts never call this function.
pub fn drawChallenges(channel: anytype, shape: Shape) !Challenges {
    try shape.validate();
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64((@as(u64, VERSION) << 32) | shape.log_domain_size);
    channel.mixU64((@as(u64, shape.log_degree_bound) << 32) | shape.original_column_count);
    return .{ .batch = channel.drawSecureFelt() };
}

/// One first-layer FRI word in the canonical pair order:
/// f_0(P) + lambda*q_0(P) + lambda^2*f_1(P) + lambda^3*q_1(P) + ... .
/// Both members of every pair must use the same authenticated source opening.
pub fn foldRow(
    original_values: []const M31,
    quotient_values: []const QM31,
    shape: Shape,
    challenges: Challenges,
) !QM31 {
    try shape.validate();
    if (original_values.len != shape.original_column_count or
        quotient_values.len != shape.original_column_count)
    {
        return error.InvalidPairedShape;
    }
    var result = QM31.zero();
    var power = QM31.one();
    for (original_values, quotient_values) |value, quotient| {
        result = result.add(power.mul(QM31.fromBase(value)));
        power = power.mul(challenges.batch);
        result = result.add(power.mul(quotient));
        power = power.mul(challenges.batch);
    }
    return result;
}

/// Materialize one uniform-domain FRI first layer. Each original and quotient
/// column has exactly the selected domain length; the caller retains ownership.
pub fn foldColumns(
    allocator: std.mem.Allocator,
    original_columns: []const []const M31,
    quotient_columns: []const []const QM31,
    shape: Shape,
    challenges: Challenges,
) ![]QM31 {
    try shape.validate();
    if (original_columns.len != shape.original_column_count or
        quotient_columns.len != shape.original_column_count)
    {
        return error.InvalidPairedShape;
    }
    const domain_size = @as(usize, 1) << @intCast(shape.log_domain_size);
    for (original_columns, quotient_columns) |source, quotient| {
        if (source.len != domain_size or quotient.len != domain_size)
            return error.InvalidPairedShape;
    }

    const coefficients = try allocator.alloc([2]QM31, original_columns.len);
    defer allocator.free(coefficients);
    var power = QM31.one();
    for (coefficients) |*pair| {
        pair[0] = power;
        power = power.mul(challenges.batch);
        pair[1] = power;
        power = power.mul(challenges.batch);
    }

    const result = try allocator.alloc(QM31, domain_size);
    for (result, 0..) |*word, row| {
        var value = QM31.zero();
        for (original_columns, quotient_columns, coefficients) |source, quotient, pair| {
            value = value.add(pair[0].mul(QM31.fromBase(source[row])));
            value = value.add(pair[1].mul(quotient[row]));
        }
        word.* = value;
    }
    return result;
}
