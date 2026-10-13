//! Experimental sampled two-height FRI relation checker.
//!
//! It checks one committed intermediate line layer and a plain low-degree
//! terminal polynomial against authenticated paired source openings at two
//! adjacent circle heights. The surrounding source envelope is versioned,
//! but this FRI section is not serialized or admitted by production PCS.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const core_utils = @import("../utils.zig");
const queries = @import("../queries.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const envelope_mod = @import("paired_envelope.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const H = envelope_mod.Hasher;

pub const IntermediateOpening = struct {
    root: H.Hash,
    /// Four QM31 coordinates, each in sampled line-query order.
    queried_coordinates: [4][]const M31,
    hash_witness: []H.Hash,
};

pub const QuerySchedule = struct {
    raw: []usize,
    source_positions: []usize,
    line_positions: []usize,

    pub fn deinit(self: *QuerySchedule, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.source_positions);
        allocator.free(self.line_positions);
        self.* = undefined;
    }
};

/// One raw largest-domain query needs four source rows (two circle folds),
/// and the two corresponding intermediate-line rows. We retain repeats so
/// the Merkle verifiers can reject inconsistent duplicate openings.
pub fn sampleQuerySchedule(
    allocator: std.mem.Allocator,
    channel: anytype,
    largest_log_size: u32,
    n_queries: usize,
) !QuerySchedule {
    if (largest_log_size < 3 or largest_log_size > 30 or n_queries == 0 or
        n_queries > (1 << 16) / 4)
    {
        return error.InvalidTwoHeightProfile;
    }
    const raw = try queries.drawQueries(channel, allocator, largest_log_size, n_queries);
    errdefer allocator.free(raw);
    const source_positions = try allocator.alloc(usize, n_queries * 4);
    errdefer allocator.free(source_positions);
    const line_positions = try allocator.alloc(usize, n_queries * 2);
    errdefer allocator.free(line_positions);
    for (raw, 0..) |position, i| {
        const source_base = position & ~@as(usize, 3);
        const line_base = (position >> 2) << 1;
        for (0..4) |j| source_positions[4 * i + j] = source_base + j;
        line_positions[2 * i] = line_base;
        line_positions[2 * i + 1] = line_base + 1;
    }
    return .{ .raw = raw, .source_positions = source_positions, .line_positions = line_positions };
}

/// Replay after `paired_envelope.decodeAndBind` has selected the source-wire
/// version and bound its verifier-chosen profile. This function draws the
/// fold challenges and sampled queries only after the intermediate root and
/// terminal polynomial are mixed. It authenticates source and intermediate
/// openings before checking both height-transition relations.
pub fn verifyAfterSourceBinding(
    allocator: std.mem.Allocator,
    channel: anytype,
    prepared: *const envelope_mod.Prepared,
    intermediate: IntermediateOpening,
    terminal_ordered_coeffs: []const QM31,
    n_queries: usize,
) !void {
    const envelope = prepared.decoded.envelope;
    if (envelope.heights.len != 2 or n_queries == 0 or
        n_queries > (1 << 16) / 4 or
        envelope.query_count != n_queries * 4)
    {
        return error.InvalidTwoHeightProfile;
    }
    const shape0 = envelope.heights[0].shape;
    const shape1 = envelope.heights[1].shape;
    if (shape0.log_domain_size < 3 or shape1.log_degree_bound < 1 or
        terminal_ordered_coeffs.len != (@as(usize, 1) << @intCast(shape1.log_degree_bound - 1)))
    {
        return error.InvalidTwoHeightProfile;
    }
    const line_domain = line.LineDomain.fromCircleDomain(
        canonic.CanonicCoset.new(shape0.log_domain_size).circleDomain(),
    );
    const terminal_domain = line.LineDomain.fromCircleDomain(
        canonic.CanonicCoset.new(shape1.log_domain_size).circleDomain(),
    );
    if (terminal_ordered_coeffs.len > terminal_domain.size()) return error.InvalidTwoHeightProfile;
    for (intermediate.queried_coordinates) |column| {
        if (column.len != n_queries * 2) return error.InvalidIntermediateShape;
    }

    const alpha0 = channel.drawSecureFelt();
    blake2_merkle.Blake2sMerkleChannel.mixRoot(channel, intermediate.root);
    const alpha1 = channel.drawSecureFelt();
    channel.mixFelts(terminal_ordered_coeffs);
    var schedule = try sampleQuerySchedule(allocator, channel, shape0.log_domain_size, n_queries);
    defer schedule.deinit(allocator);

    const source0 = try envelope_mod.authenticatedHeightAnswers(
        allocator,
        envelope,
        0,
        schedule.source_positions,
        prepared.challenges,
    );
    defer allocator.free(source0);
    const source1 = try envelope_mod.authenticatedHeightAnswers(
        allocator,
        envelope,
        1,
        schedule.source_positions,
        prepared.challenges,
    );
    defer allocator.free(source1);

    var line_verifier = try vcs_verifier.MerkleVerifierLifted(H).init(
        allocator,
        intermediate.root,
        &[_]u32{line_domain.logSize()} ** 4,
    );
    defer line_verifier.deinit(allocator);
    const queried_columns = intermediate.queried_coordinates;
    try line_verifier.verify(
        allocator,
        schedule.line_positions,
        &queried_columns,
        .{ .hash_witness = intermediate.hash_witness },
    );

    const terminal_coeffs = try allocator.dupe(QM31, terminal_ordered_coeffs);
    var terminal_poly = line.LinePoly.fromOrderedCoefficients(terminal_coeffs);
    defer terminal_poly.deinit(allocator);
    const d0 = canonic.CanonicCoset.new(shape0.log_domain_size).circleDomain();
    const d1 = canonic.CanonicCoset.new(shape1.log_domain_size).circleDomain();
    for (schedule.raw, 0..) |_, query_index| {
        const source_start = 4 * query_index;
        const line_start = 2 * query_index;
        const source_base = schedule.source_positions[source_start];
        const line_base = schedule.line_positions[line_start];
        var opened_line: [2]QM31 = undefined;
        for (0..2) |j| {
            const coordinate_index = line_start + j;
            opened_line[j] = QM31.fromM31Array(.{
                queried_columns[0][coordinate_index],
                queried_columns[1][coordinate_index],
                queried_columns[2][coordinate_index],
                queried_columns[3][coordinate_index],
            });
            const circle_row = source_base + 2 * j;
            const y = d0.at(core_utils.bitReverseIndex(circle_row, shape0.log_domain_size)).y;
            const expected = try foldPair(
                source0[source_start + 2 * j],
                source0[source_start + 2 * j + 1],
                y,
                alpha0,
            );
            if (!expected.eql(opened_line[j])) return error.IntermediateFoldMismatch;
        }
        const x = line_domain.at(core_utils.bitReverseIndex(line_base, line_domain.logSize()));
        const previous_fold = try foldPair(opened_line[0], opened_line[1], x, alpha1);
        const projected = (source_base >> 2) << 1;
        const y = d1.at(core_utils.bitReverseIndex(projected, shape1.log_domain_size)).y;
        const inserted_fold = try foldPair(source1[source_start], source1[source_start + 1], y, alpha1);
        const expected_terminal = previous_fold.add(alpha1.square().mul(inserted_fold));
        const terminal_position = source_base >> 2;
        const terminal_x = terminal_domain.at(core_utils.bitReverseIndex(
            terminal_position,
            terminal_domain.logSize(),
        ));
        const terminal_value = try terminal_poly.evalAtPoint(allocator, QM31.fromBase(terminal_x));
        if (!expected_terminal.eql(terminal_value)) return error.TerminalFoldMismatch;
    }
}

fn foldPair(even: QM31, odd: QM31, coordinate: M31, alpha: QM31) !QM31 {
    return even.add(odd).add(alpha.mul(even.sub(odd).mulM31(try coordinate.inv())));
}
