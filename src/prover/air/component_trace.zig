//! Committed trace views shared by prover AIR component capabilities.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const TreeVec = @import("stwo_core").pcs.TreeVec;
const prover_circle = @import("../poly/circle/mod.zig");

pub const Error = error{
    InvalidLogSize,
    InvalidColumnLength,
    DeviceColumnRequiresBackend,
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
    /// Explicit device polynomial; never a zero/dummy host evaluation. Its
    /// lease owner outlives this trace. Host evaluators must refuse access.
    device: ?@import("stwo_prover_api").device_pcs.DeviceCoefficients = null,

    pub fn validate(self: Poly) Error!void {
        const expected = try checkedPow2(self.log_size);
        if (self.device) |device| {
            if (self.values.len != 0 or self.coefficients != null or device.count == 0 or device.count > expected or !std.math.isPowerOfTwo(device.count) or device.context_token == 0 or device.generation == 0) return error.InvalidColumnLength;
            return;
        }
        if (self.values.len == 0) {
            const coefficients = self.coefficients orelse return error.InvalidColumnLength;
            if (coefficients.coefficients().len > expected) return error.InvalidColumnLength;
        } else if (self.values.len != expected) return error.InvalidColumnLength;
    }

    pub fn valueAtLiftingPosition(
        self: Poly,
        lifting_log_size: u32,
        position: usize,
    ) Error!M31 {
        try self.validate();
        if (self.device != null) return error.DeviceColumnRequiresBackend;
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
    partition_coefficient_composition: bool = false,
    polys: TreeVec([]const Poly),
    /// Optional execution storage for owned quotient-domain M31 values. The
    /// owner outlives this borrowed trace and every prepared evaluator. Source
    /// columns remain immutable; evaluator metadata keeps its caller allocator.
    quotient_values_allocator: ?std.mem.Allocator = null,
};

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}
