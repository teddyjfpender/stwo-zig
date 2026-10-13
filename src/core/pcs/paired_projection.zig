//! Experimental authenticated projection of largest-domain FRI queries to a
//! smaller paired source tree. This is not a multi-height FRI verifier.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const pcs_utils = @import("utils.zig");
const paired = @import("paired_ensemble.zig");
const authenticated = @import("paired_authenticated.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// Bit-reversed circle positions preserve the conjugate-pair bit and remove
/// one higher bit per circle-domain projection. Duplicates and caller order
/// are retained because they determine how source answers map back to raw
/// largest-domain FRI queries.
pub fn projectPositions(
    allocator: std.mem.Allocator,
    largest_positions: []const usize,
    largest_log_size: u32,
    target_log_size: u32,
) ![]usize {
    if (largest_log_size < 2 or largest_log_size > 30 or
        target_log_size < 2 or target_log_size > largest_log_size)
    {
        return error.InvalidProjectionGeometry;
    }
    const largest_size = @as(usize, 1) << @intCast(largest_log_size);
    for (largest_positions) |position| {
        if (position >= largest_size) return error.QueryPositionOutOfRange;
    }
    return pcs_utils.prepareTreeQueryPositions(
        allocator,
        largest_positions,
        largest_log_size,
        target_log_size,
    );
}

/// Authenticates one height's source openings at its projected positions,
/// then derives that height's paired answers in largest-query order. The
/// supplied verifier must be rooted in a prior committed source tree.
pub fn authenticatedProjectedAnswers(
    comptime H: type,
    allocator: std.mem.Allocator,
    largest_positions: []const usize,
    largest_log_size: u32,
    source_verifier: vcs_verifier.MerkleVerifierLifted(H),
    queried_sources: []const []const M31,
    source_decommitment: vcs_verifier.MerkleDecommitmentLifted(H),
    sample_points: []const circle.CirclePointQM31,
    sample_values: []const QM31,
    shape: paired.Shape,
    challenges: paired.Challenges,
) ![]QM31 {
    const projected = try projectPositions(
        allocator,
        largest_positions,
        largest_log_size,
        shape.log_domain_size,
    );
    defer allocator.free(projected);
    return authenticated.authenticatedAnswers(
        H,
        allocator,
        source_verifier,
        projected,
        queried_sources,
        source_decommitment,
        sample_points,
        sample_values,
        shape,
        challenges,
    );
}
