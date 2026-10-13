//! Experimental authenticated-query bridge for a uniform-domain paired batch.
//!
//! This routine accepts only a Merkle verifier rooted in the committed source
//! tree. It authenticates every queried source value before deriving each
//! native two-point OOD quotient from that very value and folding the pair.
//! It is not a serialized PCS verifier and does not assert P05 soundness.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const core_utils = @import("../utils.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const quotients = @import("quotients.zig");
const paired = @import("paired_ensemble.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;

pub fn authenticatedAnswers(
    comptime H: type,
    allocator: std.mem.Allocator,
    source_verifier: vcs_verifier.MerkleVerifierLifted(H),
    query_positions: []const usize,
    queried_sources: []const []const M31,
    source_decommitment: vcs_verifier.MerkleDecommitmentLifted(H),
    sample_points: []const CirclePointQM31,
    sample_values: []const QM31,
    shape: paired.Shape,
    challenges: paired.Challenges,
) ![]QM31 {
    try shape.validate();
    const column_count: usize = @intCast(shape.original_column_count);
    if (source_verifier.height != shape.log_domain_size or
        source_verifier.column_log_sizes.len != column_count or
        queried_sources.len != column_count or
        sample_points.len != column_count or
        sample_values.len != column_count)
    {
        return error.InvalidPairedShape;
    }
    for (source_verifier.column_log_sizes, queried_sources) |log_size, values| {
        if (log_size != shape.log_domain_size or values.len != query_positions.len)
            return error.InvalidPairedShape;
    }

    // The bridge cannot expose a first-layer answer until all source columns
    // have passed the same compressed multiproof against the committed root.
    try source_verifier.verify(
        allocator,
        query_positions,
        queried_sources,
        source_decommitment,
    );

    const domain = canonic.CanonicCoset.new(shape.log_domain_size).circleDomain();
    const answers = try allocator.alloc(QM31, query_positions.len);
    errdefer allocator.free(answers);
    @memset(answers, QM31.zero());

    var power = QM31.one();
    for (queried_sources, sample_points, sample_values) |source, point, claim| {
        const source_coefficient = power;
        power = power.mul(challenges.batch);
        const quotient_coefficient = power;
        power = power.mul(challenges.batch);

        var sample = [_]quotients.NumeratorData{.{
            .column_index = 0,
            .sample_value = claim,
            .random_coeff = QM31.one(),
        }};
        var batches = [_]quotients.ColumnSampleBatch{.{
            .point = point,
            .cols_vals_randpows = sample[0..],
        }};
        var constants = try quotients.quotientConstants(allocator, batches[0..]);
        defer constants.deinit(allocator);
        var workspace = try quotients.RowQuotientWorkspace.init(allocator, batches[0..]);
        defer workspace.deinit(allocator);

        for (query_positions, source, answers) |position, source_value, *answer| {
            if (position >= domain.size()) return error.QueryPositionOutOfRange;
            const domain_point = domain.at(core_utils.bitReverseIndex(position, shape.log_domain_size));
            const quotient = try quotients.accumulateRowQuotientsWithWorkspace(
                batches[0..],
                &[_]M31{source_value},
                &constants,
                domain_point,
                &workspace,
            );
            answer.* = answer.*.add(source_coefficient.mul(QM31.fromBase(source_value)));
            answer.* = answer.*.add(quotient_coefficient.mul(quotient));
        }
    }
    return answers;
}
