//! Committed trace views shared by prover AIR component capabilities.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const TreeVec = @import("stwo_core").pcs.TreeVec;
const prover_circle = @import("../poly/circle/mod.zig");

pub const Error = error{
    InvalidLogSize,
    InvalidColumnLength,
};

/// Trace column retained by the commitment scheme.
///
/// `log_size` and `values` describe the committed LDE column, not the base
/// trace degree. `coefficients`, when present, is a non-owning view of the
/// minimal trace polynomial in the circle FFT basis.
pub const Poly = struct {
    log_size: u32,
    values: []const M31,
    /// Constraint evaluators use these to evaluate on domains other than the
    /// committed LDE. The commitment tree remains the owner.
    coefficients: ?prover_circle.CircleCoefficients = null,

    pub fn validate(self: Poly) Error!void {
        const expected = try checkedPow2(self.log_size);
        if (self.values.len != expected) return error.InvalidColumnLength;
    }

    pub fn valueAtLiftingPosition(
        self: Poly,
        lifting_log_size: u32,
        position: usize,
    ) Error!M31 {
        try self.validate();
        if (self.log_size > lifting_log_size) return error.InvalidLogSize;

        const lifting_size = try checkedPow2(lifting_log_size);
        if (position >= lifting_size) return error.InvalidColumnLength;

        const shift = lifting_log_size - self.log_size;
        if (shift >= @bitSizeOf(usize)) return error.InvalidLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
        const index = ((position >> shift_amt) << 1) + (position & 1);
        if (index >= self.values.len) return error.InvalidColumnLength;
        return self.values[index];
    }
};

pub const Trace = struct {
    polys: TreeVec([]const Poly),
};

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}
