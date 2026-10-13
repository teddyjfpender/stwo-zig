//! Experimental, single-domain paired FRI input for degree-corrected openings.
//!
//! This is an arithmetic/transcript building block, not an admitted PCS proof
//! mode. In particular, callers must authenticate every original column and
//! derive the quotient from those same columns and claimed OOD values. The
//! multi-domain degree alignment and proof envelope are not implemented here.

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
    original_column_count: u32,

    pub fn validate(self: Shape) !void {
        if (self.log_domain_size < 2 or self.log_domain_size > 30 or
            self.log_degree_bound >= self.log_domain_size or
            self.original_column_count == 0)
        {
            return error.InvalidPairedShape;
        }
    }
};

pub const Challenges = struct {
    originals: QM31,
    quotient: QM31,
};

/// Bind the new mode and its uniform degree geometry before drawing batching
/// challenges. This must occur after source commitments and claimed OOD values
/// have been mixed. Legacy PCS transcripts never call this function.
pub fn drawChallenges(channel: anytype, shape: Shape) !Challenges {
    try shape.validate();
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64((@as(u64, VERSION) << 32) | shape.log_domain_size);
    channel.mixU64((@as(u64, shape.log_degree_bound) << 32) | shape.original_column_count);
    return .{
        .originals = channel.drawSecureFelt(),
        .quotient = channel.drawSecureFelt(),
    };
}

/// One first-layer FRI word: sum_j gamma^j f_j(P) + eta q(P). The source
/// columns are included once each, even when a column has many OOD samples.
pub fn foldRow(
    original_values: []const M31,
    quotient_value: QM31,
    shape: Shape,
    challenges: Challenges,
) !QM31 {
    try shape.validate();
    if (original_values.len != shape.original_column_count)
        return error.InvalidPairedShape;
    var result = QM31.zero();
    var power = QM31.one();
    for (original_values) |value| {
        result = result.add(power.mul(QM31.fromBase(value)));
        power = power.mul(challenges.originals);
    }
    return result.add(challenges.quotient.mul(quotient_value));
}

/// Materialize an experimental FRI first layer from authenticated source
/// columns and a separately computed quotient. No proof envelope is emitted.
pub fn foldColumns(
    allocator: std.mem.Allocator,
    original_columns: []const []const M31,
    quotient: []const QM31,
    shape: Shape,
    challenges: Challenges,
) ![]QM31 {
    try shape.validate();
    if (original_columns.len != shape.original_column_count or
        quotient.len != (@as(usize, 1) << @intCast(shape.log_domain_size)))
    {
        return error.InvalidPairedShape;
    }
    for (original_columns) |column| {
        if (column.len != quotient.len) return error.InvalidPairedShape;
    }

    const coefficients = try allocator.alloc(QM31, original_columns.len);
    defer allocator.free(coefficients);
    var power = QM31.one();
    for (coefficients) |*coefficient| {
        coefficient.* = power;
        power = power.mul(challenges.originals);
    }

    const result = try allocator.alloc(QM31, quotient.len);
    for (result, quotient, 0..) |*word, q, row| {
        var value = QM31.zero();
        for (original_columns, coefficients) |column, coefficient| {
            value = value.add(coefficient.mul(QM31.fromBase(column[row])));
        }
        word.* = value.add(challenges.quotient.mul(q));
    }
    return result;
}
