//! Deterministic host prover for the sparse XDM04/CAS05 cascade harness.
//! It materializes every domain and is not a production proving backend.

const std = @import("std");
const core = @import("stwo_core");
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const canonic = core.poly.circle.canonic;
const cascade = core.pcs.paired_sparse_cascade_experimental;
const sparse = core.pcs.transposed_merkle_sparse;
const source_prover = @import("transposed_cascade_experimental.zig");
const old = @import("paired_two_height_experimental.zig");
const SourceProver = @import("../vcs_lifted/prover.zig").MerkleProverLifted(core.pcs.paired_envelope.Hasher);
const LineEvaluation = @import("../line.zig").LineEvaluation;

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const Input = struct {
    source_columns: []const []const []const M31,
    log_blowup: u32,
    n_queries: usize,
};

pub const OwnedProof = struct {
    arena: std.heap.ArenaAllocator,
    proof: cascade.Proof,
    pub fn deinit(self: *OwnedProof) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn prove(
    allocator: std.mem.Allocator,
    input: Input,
    channel: anytype,
) !OwnedProof {
    return proveImpl(allocator, input, channel, .none);
}

/// Adversarial test helper: authentic source and line commitments/openings are
/// sampled for a deliberately false terminal polynomial. The resulting proof
/// must pass Merkle checks and fail the final fold relation.
pub fn proveWithInvalidTerminalForTest(
    allocator: std.mem.Allocator,
    input: Input,
    channel: anytype,
) !OwnedProof {
    return proveImpl(allocator, input, channel, .terminal);
}

/// Commit a wrong first line under a valid Merkle tree, then sample/open
/// consistently. The verifier must reach the intermediate fold check.
pub fn proveWithInvalidLineForTest(
    allocator: std.mem.Allocator,
    input: Input,
    channel: anytype,
) !OwnedProof {
    return proveImpl(allocator, input, channel, .line);
}

const Corruption = enum { none, line, terminal };

fn proveImpl(
    allocator: std.mem.Allocator,
    input: Input,
    channel: anytype,
    corruption: Corruption,
) !OwnedProof {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var source = try source_prover.Commitment.commit(a, input.source_columns);
    const root = source.root();
    const source_profile = sparse.Profile{
        .largest_log_size = source.profile.largest_log_size,
        .height_count = source.profile.height_count,
        .columns = source.profile.columns,
        .query_count = input.n_queries,
    };
    const profile = cascade.Profile{ .source = source_profile, .log_blowup = input.log_blowup };
    try profile.validate();
    const height_count = source_profile.height_count;
    const domains = try a.alloc(core.poly.circle.domain.CircleDomain, height_count);
    const claims = try a.alloc([]const QM31, height_count);
    const batches = try a.alloc([]QM31, height_count);
    for (input.source_columns, 0..) |columns, i| {
        const log_size = source_profile.largest_log_size - @as(u32, @intCast(i));
        domains[i] = canonic.CanonicCoset.new(log_size).circleDomain();
        try old.validateSourceDegree(a, domains[i], columns, log_size - input.log_blowup);
    }
    var staged = channel.*;
    cascade.bindVersion(&staged);
    const point = try core.pcs.paired_cascade_experimental.drawOodPoint(&staged, profile, root);
    for (input.source_columns, 0..) |columns, i| {
        const values = try a.alloc(QM31, columns.len);
        try old.evaluateClaims(a, domains[i], columns, point, values);
        claims[i] = values;
    }
    const batch = core.pcs.paired_cascade_experimental.drawBatchAfterOod(&staged, claims);
    const challenges = core.pcs.paired_ensemble.Challenges{ .batch = batch };
    for (input.source_columns, 0..) |columns, i|
        batches[i] = try old.pairedHeight(a, domains[i], columns, claims[i], point, challenges);

    const line_count = height_count - 1;
    const trees = try a.alloc(SourceProver, line_count);
    const columns_by_line = try a.alloc([4][]const M31, line_count);
    var current_values: []QM31 = undefined;
    var current_domain: core.poly.line.LineDomain = undefined;
    for (0..line_count) |step| {
        const alpha = staged.drawSecureFelt();
        if (step == 0) {
            current_values = try a.alloc(QM31, batches[0].len / 2);
            @memset(current_values, QM31.zero());
            var workspace = try core.fri.folding.FoldCircleWorkspace.init(a, current_values.len);
            try core.fri.folding.foldCircleIntoLineWithWorkspace(
                a,
                current_values,
                batches[0],
                domains[0],
                alpha,
                &workspace,
            );
            current_domain = core.poly.line.LineDomain.fromCircleDomain(domains[0]);
        } else {
            const result = try core.fri.multidomain_insertion.insertCircleBatch(
                a,
                current_values,
                current_domain,
                batches[step],
                domains[step],
                alpha,
            );
            current_values = result.values;
            current_domain = result.domain;
        }
        var line_columns: [4][]const M31 = undefined;
        var storage: [4][]M31 = undefined;
        for (&storage, &line_columns) |*values, *column| {
            values.* = try a.alloc(M31, current_values.len);
            column.* = values.*;
        }
        for (current_values, 0..) |value, row| {
            const coordinates = value.toM31Array();
            for (storage, coordinates) |column, coordinate| column[row] = coordinate;
        }
        if (corruption == .line and step == 0) {
            for (storage[0]) |*coordinate| coordinate.* = coordinate.*.add(M31.one());
        }
        columns_by_line[step] = line_columns;
        trees[step] = try SourceProver.commit(a, &columns_by_line[step]);
        core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, trees[step].root());
    }
    const last_alpha = staged.drawSecureFelt();
    const last = try core.fri.multidomain_insertion.insertCircleBatch(
        a,
        current_values,
        current_domain,
        batches[height_count - 1],
        domains[height_count - 1],
        last_alpha,
    );
    var evaluation = try LineEvaluation.initBorrowed(last.domain, last.values);
    var polynomial = try evaluation.interpolate(a);
    const ordered = polynomial.intoOrderedCoefficients();
    const terminal_len = profile.terminalLength();
    for (ordered[terminal_len..]) |coefficient|
        if (!coefficient.isZero()) {
            return error.TerminalDegreeExceeded;
        };
    const terminal = if (corruption == .terminal) blk: {
        const changed = try a.dupe(QM31, ordered[0..terminal_len]);
        changed[0] = changed[0].add(QM31.one());
        break :blk changed;
    } else ordered[0..terminal_len];
    staged.mixFelts(terminal);
    const raw = try core.queries.drawQueries(
        &staged,
        a,
        source_profile.largest_log_size,
        input.n_queries,
    );
    const source_wire = try source.encodeSparseOpenings(a, raw);
    const line_openings = try a.alloc(cascade.LineOpening, line_count);
    for (0..line_count) |i| {
        const height = i + 1;
        const width: usize = 2;
        const rows = try a.alloc(usize, input.n_queries * width);
        for (raw, 0..) |position, query| {
            const base = sparse.pairBase(position, height);
            for (0..width) |j| rows[query * width + j] = base + j;
        }
        const decommitment = try trees[i].decommit(a, rows, &columns_by_line[i]);
        line_openings[i] = .{
            .root = trees[i].root(),
            .queried_coordinates = .{
                decommitment.queried_values[0], decommitment.queried_values[1],
                decommitment.queried_values[2], decommitment.queried_values[3],
            },
            .hash_witness = decommitment.decommitment.decommitment.hash_witness,
        };
    }
    channel.* = staged;
    return .{ .arena = arena, .proof = .{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .claims = claims,
        .source_wire = source_wire,
        .line_openings = line_openings,
        .terminal_ordered_coeffs = terminal,
    } };
}
