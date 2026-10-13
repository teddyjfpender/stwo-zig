//! Experimental deterministic prover for the versioned two-height paired FRI
//! wire proof. Production PCS never calls this module. It is a compact host
//! reference for transcript, quotient, fold, and opening correspondence, not
//! an admitted security profile or optimized proving backend.

const std = @import("std");
const core = @import("stwo_core");
const circle = core.circle;
const constraints = core.constraints;
const m31 = core.fields.m31;
const cm31 = core.fields.cm31;
const qm31 = core.fields.qm31;
const canonic = core.poly.circle.canonic;
const envelope_mod = core.pcs.paired_envelope;
const paired = core.pcs.paired_ensemble;
const wire = core.pcs.paired_two_height_wire;
const two_height = core.pcs.paired_two_height_fri;
const SourceProver = @import("../vcs_lifted/prover.zig").MerkleProverLifted(envelope_mod.Hasher);
const CircleEvaluation = @import("../poly/circle/evaluation.zig").CircleEvaluation;
const circle_poly = @import("../poly/circle/poly.zig");
const LineEvaluation = @import("../line.zig").LineEvaluation;

const M31 = m31.M31;
const CM31 = cm31.CM31;
const QM31 = qm31.QM31;

pub const Input = struct {
    largest_log_size: u32,
    log_blowup: u32,
    n_queries: usize,
    /// Borrowed source evaluations in native bit-reversed circle-row order.
    first_columns: []const []const M31,
    second_columns: []const []const M31,

    pub fn shapes(self: Input) ![2]paired.Shape {
        if (self.largest_log_size < 4 or self.largest_log_size > 16 or
            self.log_blowup == 0 or self.log_blowup + 1 >= self.largest_log_size or
            self.n_queries == 0 or self.n_queries > (1 << 16) / 4 or
            self.first_columns.len == 0 or self.first_columns.len > 64 or
            self.second_columns.len == 0 or self.second_columns.len > 64)
        {
            return error.InvalidPairedProverInput;
        }
        const second_log = self.largest_log_size - 1;
        const first_size = @as(usize, 1) << @intCast(self.largest_log_size);
        const second_size = first_size / 2;
        for (self.first_columns) |column| {
            if (column.len != first_size) return error.InvalidPairedProverInput;
        }
        for (self.second_columns) |column| {
            if (column.len != second_size) return error.InvalidPairedProverInput;
        }
        return .{
            .{
                .log_domain_size = self.largest_log_size,
                .log_degree_bound = self.largest_log_size - self.log_blowup,
                .original_column_count = @intCast(self.first_columns.len),
            },
            .{
                .log_domain_size = second_log,
                .log_degree_bound = second_log - self.log_blowup,
                .original_column_count = @intCast(self.second_columns.len),
            },
        };
    }
};

/// Produce one S31P2F01 proof from source evaluations. The caller's channel is
/// updated only after proof construction succeeds. The returned bytes are
/// owned by `allocator`; all trees, columns, and witnesses are temporary.
pub fn prove(allocator: std.mem.Allocator, input: Input, channel: anytype) ![]u8 {
    const shapes = try input.shapes();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first_domain = canonic.CanonicCoset.new(input.largest_log_size).circleDomain();
    const second_domain = canonic.CanonicCoset.new(input.largest_log_size - 1).circleDomain();
    try validateSourceDegree(a, first_domain, input.first_columns, shapes[0].log_degree_bound);
    try validateSourceDegree(a, second_domain, input.second_columns, shapes[1].log_degree_bound);
    var first_tree = try SourceProver.commit(a, input.first_columns);
    defer first_tree.deinit(a);
    var second_tree = try SourceProver.commit(a, input.second_columns);
    defer second_tree.deinit(a);

    const first_points = try a.alloc(circle.CirclePointQM31, input.first_columns.len);
    const second_points = try a.alloc(circle.CirclePointQM31, input.second_columns.len);
    @memset(first_points, circle.CirclePointQM31.zero());
    @memset(second_points, circle.CirclePointQM31.zero());
    const first_claims = try a.alloc(QM31, input.first_columns.len);
    const second_claims = try a.alloc(QM31, input.second_columns.len);
    @memset(first_claims, QM31.zero());
    @memset(second_claims, QM31.zero());
    const dummy_values = try a.alloc(M31, 4 * input.n_queries);
    @memset(dummy_values, M31.zero());
    const first_dummy = try a.alloc([]const M31, input.first_columns.len);
    const second_dummy = try a.alloc([]const M31, input.second_columns.len);
    @memset(first_dummy, dummy_values);
    @memset(second_dummy, dummy_values);
    const empty_witness = try a.alloc(envelope_mod.Hash, 0);
    const header_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shapes[0],
            .source_root = first_tree.root(),
            .sample_points = first_points,
            .sample_values = first_claims,
            .queried_sources = first_dummy,
            .hash_witness = empty_witness,
        },
        .{
            .shape = shapes[1],
            .source_root = second_tree.root(),
            .sample_points = second_points,
            .sample_values = second_claims,
            .queried_sources = second_dummy,
            .hash_witness = empty_witness,
        },
    };
    const header = envelope_mod.Envelope{
        .largest_log_size = input.largest_log_size,
        .query_count = @intCast(4 * input.n_queries),
        .heights = &header_heights,
    };
    var staged_channel = channel.*;
    wire.bindVersion(&staged_channel);
    const sampled_point = try wire.drawOodPointFromRoots(&staged_channel, header);
    @memset(first_points, sampled_point);
    @memset(second_points, sampled_point);
    try evaluateClaims(a, first_domain, input.first_columns, sampled_point, first_claims);
    try evaluateClaims(a, second_domain, input.second_columns, sampled_point, second_claims);
    const challenges = try wire.drawBatchAfterOod(&staged_channel, header, sampled_point);

    const alpha0 = staged_channel.drawSecureFelt();
    const first_batch = try pairedHeight(a, first_domain, input.first_columns, first_claims, sampled_point, challenges);
    const second_batch = try pairedHeight(a, second_domain, input.second_columns, second_claims, sampled_point, challenges);
    const line_values = try a.alloc(QM31, first_batch.len / 2);
    @memset(line_values, QM31.zero());
    var circle_workspace = try core.fri.folding.FoldCircleWorkspace.init(a, line_values.len);
    defer circle_workspace.deinit(a);
    try core.fri.folding.foldCircleIntoLineWithWorkspace(
        a,
        line_values,
        first_batch,
        first_domain,
        alpha0,
        &circle_workspace,
    );
    var line_storage: [4][]M31 = undefined;
    var line_columns: [4][]const M31 = undefined;
    for (&line_storage, &line_columns) |*storage, *column| {
        storage.* = try a.alloc(M31, line_values.len);
        column.* = storage.*;
    }
    for (line_values, 0..) |value, row| {
        const coordinates = value.toM31Array();
        for (line_storage, coordinates) |column, coordinate| column[row] = coordinate;
    }
    var line_tree = try SourceProver.commit(a, &line_columns);
    defer line_tree.deinit(a);
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged_channel, line_tree.root());
    const alpha1 = staged_channel.drawSecureFelt();
    const last_line = try core.fri.multidomain_insertion.insertCircleBatch(
        a,
        line_values,
        core.poly.line.LineDomain.fromCircleDomain(first_domain),
        second_batch,
        second_domain,
        alpha1,
    );
    var evaluation = try LineEvaluation.initBorrowed(last_line.domain, last_line.values);
    var polynomial = try evaluation.interpolate(a);
    defer polynomial.deinit(a);
    const ordered_coeffs = polynomial.intoOrderedCoefficients();
    const terminal_len = @as(usize, 1) << @intCast(shapes[1].log_degree_bound - 1);
    for (ordered_coeffs[terminal_len..]) |coefficient| {
        if (!coefficient.isZero()) return error.TerminalDegreeExceeded;
    }
    const terminal_coeffs = ordered_coeffs[0..terminal_len];
    staged_channel.mixFelts(terminal_coeffs);
    var schedule = try two_height.sampleQuerySchedule(
        a,
        &staged_channel,
        input.largest_log_size,
        input.n_queries,
    );
    defer schedule.deinit(a);
    const second_positions = try core.pcs.paired_projection.projectPositions(
        a,
        schedule.source_positions,
        input.largest_log_size,
        input.largest_log_size - 1,
    );
    var first_opened = try first_tree.decommit(a, schedule.source_positions, input.first_columns);
    defer first_opened.deinit(a);
    var second_opened = try second_tree.decommit(a, second_positions, input.second_columns);
    defer second_opened.deinit(a);
    var line_opened = try line_tree.decommit(a, schedule.line_positions, &line_columns);
    defer line_opened.deinit(a);
    const first_queried = try borrowedColumns(a, first_opened.queried_values);
    const second_queried = try borrowedColumns(a, second_opened.queried_values);
    const heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shapes[0],
            .source_root = first_tree.root(),
            .sample_points = first_points,
            .sample_values = first_claims,
            .queried_sources = first_queried,
            .hash_witness = first_opened.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shapes[1],
            .source_root = second_tree.root(),
            .sample_points = second_points,
            .sample_values = second_claims,
            .queried_sources = second_queried,
            .hash_witness = second_opened.decommitment.decommitment.hash_witness,
        },
    };
    const source_bytes = try envelope_mod.encode(a, .{
        .largest_log_size = input.largest_log_size,
        .query_count = @intCast(4 * input.n_queries),
        .heights = &heights,
    });
    const proof_bytes = try wire.encode(allocator, .{
        .source_wire = source_bytes,
        .intermediate = .{
            .root = line_tree.root(),
            .queried_coordinates = .{
                line_opened.queried_values[0], line_opened.queried_values[1],
                line_opened.queried_values[2], line_opened.queried_values[3],
            },
            .hash_witness = line_opened.decommitment.decommitment.hash_witness,
        },
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    channel.* = staged_channel;
    return proof_bytes;
}

fn evaluateClaims(
    allocator: std.mem.Allocator,
    domain: core.poly.circle.domain.CircleDomain,
    columns: []const []const M31,
    point: circle.CirclePointQM31,
    claims: []QM31,
) !void {
    const weights = try CircleEvaluation.barycentricWeights(
        allocator,
        canonic.CanonicCoset.new(domain.logSize()),
        point,
    );
    for (columns, claims) |column, *claim| {
        const evaluation = try CircleEvaluation.init(domain, column);
        claim.* = try evaluation.barycentricEvalAtPointWithWeights(weights);
    }
}

fn validateSourceDegree(
    allocator: std.mem.Allocator,
    domain: core.poly.circle.domain.CircleDomain,
    columns: []const []const M31,
    log_degree_bound: u32,
) !void {
    const bound = @as(usize, 1) << @intCast(log_degree_bound);
    for (columns) |column| {
        const evaluation = try CircleEvaluation.init(domain, column);
        var polynomial = try circle_poly.interpolateFromEvaluation(allocator, evaluation);
        defer polynomial.deinit(allocator);
        for (polynomial.coefficients()[bound..]) |coefficient| {
            if (!coefficient.isZero()) return error.SourceDegreeExceeded;
        }
    }
}

fn pairedHeight(
    allocator: std.mem.Allocator,
    domain: core.poly.circle.domain.CircleDomain,
    columns: []const []const M31,
    claims: []const QM31,
    point: circle.CirclePointQM31,
    challenges: paired.Challenges,
) ![]QM31 {
    const coefficients = try allocator.alloc(constraints.LineCoeffs, columns.len);
    for (claims, coefficients) |claim, *coefficient| {
        coefficient.* = try constraints.complexConjugateLineCoeffs(point, claim, QM31.one());
    }
    const powers = try allocator.alloc([2]QM31, columns.len);
    var power = QM31.one();
    for (powers) |*pair| {
        pair[0] = power;
        power = power.mul(challenges.batch);
        pair[1] = power;
        power = power.mul(challenges.batch);
    }
    const output = try allocator.alloc(QM31, domain.size());
    for (output, 0..) |*result, row| {
        const p = domain.at(core.utils.bitReverseIndex(row, domain.logSize()));
        const denominator = point.x.c0.sub(CM31.fromBase(p.x)).mul(point.y.c1)
            .sub(point.y.c0.sub(CM31.fromBase(p.y)).mul(point.x.c1));
        const inverse = try denominator.inv();
        var value = QM31.zero();
        for (columns, coefficients, powers) |column, coefficient, pair| {
            const numerator = coefficient.c.mulM31(column[row])
                .sub(coefficient.a.mulM31(p.y)).sub(coefficient.b);
            const quotient = numerator.mulCM31(inverse);
            value = value.add(pair[0].mul(QM31.fromBase(column[row])))
                .add(pair[1].mul(quotient));
        }
        result.* = value;
    }
    return output;
}

fn borrowedColumns(allocator: std.mem.Allocator, columns: []const []M31) ![]const []const M31 {
    const result = try allocator.alloc([]const M31, columns.len);
    for (columns, result) |column, *dst| dst.* = column;
    return result;
}
