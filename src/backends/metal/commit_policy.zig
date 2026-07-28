//! Shared cost model for Metal-backed lifted Merkle commitments.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const telemetry = @import("telemetry.zig");

/// A Metal-labelled proof admits every non-empty commitment to the resident
/// implementation. Performance selection belongs to an explicitly hybrid
/// product; it cannot silently move work to CPU under this policy.
pub const merkle_cell_threshold: usize = 1;

/// Every valid lifted quotient domain is resident in the strict Metal product.
pub const quotient_resident_merkle_log_threshold: u32 = 1;

/// Fold and commit in one device epoch at every non-trivial FRI layer.
pub const fri_fold_commit_log_threshold: u32 = 1;

pub fn usesResidentMerkle(cell_count: usize) bool {
    return cell_count >= merkle_cell_threshold;
}

/// Whether a QM31 evaluation's four coordinate planes will use resident Merkle.
/// Overflow cannot describe a valid host allocation, so it stays on the resident
/// route and lets the commitment's checked size calculation report the error.
pub fn secureColumnUsesResidentMerkle(value_count: usize) bool {
    const cell_count = std.math.mul(
        usize,
        value_count,
        qm31.SECURE_EXTENSION_DEGREE,
    ) catch return true;
    return usesResidentMerkle(cell_count);
}

pub fn quotientUsesResidentMerkle(lifting_log_size: u32) bool {
    return lifting_log_size >= quotient_resident_merkle_log_threshold;
}

pub fn friFoldCommitUsesResidentMerkle(value_count: usize, fold_count: u32) bool {
    if (fold_count != 1 or value_count == 0 or !std.math.isPowerOfTwo(value_count)) return false;
    return std.math.log2_int(usize, value_count) >= fri_fold_commit_log_threshold;
}

/// A sampled-value evaluation that declined the device route is a counted CPU
/// fallback, not a placement.
pub fn recordSampledValueFallback() void {
    telemetry.record(.cpu_sampled_value_evaluation);
}
