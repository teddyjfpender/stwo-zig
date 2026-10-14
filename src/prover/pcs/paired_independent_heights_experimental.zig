//! Experimental CAS09 host prover with separate original and own-quotient
//! multi-height FRI tracks. All source and line domains are materialized.
//! No production PCS mode selects this path.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Channel = core.channel.blake2s.Blake2sChannel;
const cascade = core.pcs.paired_independent_heights_experimental;
const dual_rows = core.pcs.paired_independent_h1_experimental;
const sparse = core.pcs.transposed_merkle_sparse_heights_experimental;
const source_prover = @import("transposed_sparse_heights_experimental.zig");
const old = @import("paired_two_height_experimental.zig");
const SourceProver = @import("../vcs_lifted/prover.zig").MerkleProverLifted(core.pcs.paired_envelope.Hasher);
const LineEvaluation = @import("../line.zig").LineEvaluation;
const s31_prelude = core.pcs.s31_cas05_prelude_experimental;

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

fn terminal(allocator: std.mem.Allocator, domain: core.poly.line.LineDomain, values: []const QM31, bound: usize) ![]const QM31 {
    var evaluation = try LineEvaluation.initBorrowed(domain, values);
    var polynomial = try evaluation.interpolate(allocator);
    const ordered = polynomial.intoOrderedCoefficients();
    for (ordered[bound..]) |coefficient|
        if (!coefficient.isZero()) return error.TerminalDegreeExceeded;
    return ordered[0..bound];
}

pub fn prove(allocator: std.mem.Allocator, input: Input, channel: *Channel) !OwnedProof {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var source = try source_prover.Commitment.commit(a, input.source_columns, input.n_queries);
    const source_profile = sparse.Profile{
        .largest_log_size = source.profile.largest_log_size,
        .height_count = source.profile.height_count,
        .columns = source.profile.columns,
        .query_count = input.n_queries,
    };
    const profile = cascade.Profile{ .source = source_profile, .log_blowup = input.log_blowup };
    try profile.validate();
    const root = source.root();
    const height_count = source_profile.height_count;
    const domains = try a.alloc(core.poly.circle.domain.CircleDomain, height_count);
    const claims = try a.alloc([]const QM31, height_count);
    const batches = try a.alloc([2][]QM31, height_count);
    for (input.source_columns, 0..) |columns, i| {
        const log_size = source_profile.largest_log_size - @as(u32, @intCast(i));
        domains[i] = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
        if (columns.len > 0)
            try old.validateSourceDegree(a, domains[i], columns, log_size - input.log_blowup);
    }
    var staged = channel.*;
    cascade.bindVersion(&staged);
    const point = try cascade.drawOodPoint(&staged, profile, root);
    for (input.source_columns, 0..) |columns, i| {
        const values = try a.alloc(QM31, columns.len);
        if (columns.len > 0) try old.evaluateClaims(a, domains[i], columns, point, values);
        claims[i] = values;
    }
    const batch = try cascade.drawBatchAfterOod(&staged, claims);
    for (input.source_columns, 0..) |columns, i| {
        const size = domains[i].size();
        batches[i] = .{ try a.alloc(QM31, size), try a.alloc(QM31, size) };
        if (columns.len == 0) {
            for (batches[i]) |words| @memset(words, QM31.zero());
            continue;
        }
        var context = try dual_rows.RowContext.init(a, point, claims[i], batch);
        for (0..size) |row| {
            const p = domains[i].at(core.utils.bitReverseIndex(row, domains[i].logSize()));
            const words = try context.dense(columns, row, p);
            for (0..2) |track| batches[i][track][row] = words[track];
        }
        context.deinit();
    }

    const line_count = height_count - 1;
    const trees = try a.alloc([2]SourceProver, line_count);
    const columns_by_line = try a.alloc([2][4][]const M31, line_count);
    var current_values: [2][]QM31 = undefined;
    var current_domain: core.poly.line.LineDomain = undefined;
    for (0..line_count) |step| {
        const alpha = staged.drawSecureFelt();
        var next_domain: core.poly.line.LineDomain = undefined;
        for (0..2) |track| {
            if (step == 0) {
                current_values[track] = try a.alloc(QM31, batches[0][track].len / 2);
                @memset(current_values[track], QM31.zero());
                var workspace = try core.fri.folding.FoldCircleWorkspace.init(a, current_values[track].len);
                try core.fri.folding.foldCircleIntoLineWithWorkspace(
                    a,
                    current_values[track],
                    batches[0][track],
                    domains[0],
                    alpha,
                    &workspace,
                );
                next_domain = core.poly.line.LineDomain.fromCircleDomain(domains[0]);
            } else {
                const result = try core.fri.multidomain_insertion.insertCircleBatch(
                    a,
                    current_values[track],
                    current_domain,
                    batches[step][track],
                    domains[step],
                    alpha,
                );
                current_values[track] = result.values;
                next_domain = result.domain;
            }
        }
        current_domain = next_domain;
        for (0..2) |track| {
            var columns: [4][]const M31 = undefined;
            var storage: [4][]M31 = undefined;
            for (&storage, &columns) |*values, *column| {
                values.* = try a.alloc(M31, current_values[track].len);
                column.* = values.*;
            }
            for (current_values[track], 0..) |value, row| {
                const coordinates = value.toM31Array();
                for (storage, coordinates) |column, coordinate| column[row] = coordinate;
            }
            columns_by_line[step][track] = columns;
            trees[step][track] = try SourceProver.commit(a, &columns_by_line[step][track]);
            cascade.mixLineRoot(&staged, step, track, trees[step][track].root());
        }
    }
    const last_alpha = staged.drawSecureFelt();
    var terminals: [2][]const QM31 = undefined;
    for (0..2) |track| {
        const last: core.fri.folding.FoldLineResult = if (height_count == 1) blk: {
            const values = try a.alloc(QM31, batches[0][track].len / 2);
            @memset(values, QM31.zero());
            var workspace = try core.fri.folding.FoldCircleWorkspace.init(a, values.len);
            try core.fri.folding.foldCircleIntoLineWithWorkspace(a, values, batches[0][track], domains[0], last_alpha, &workspace);
            break :blk .{ .domain = core.poly.line.LineDomain.fromCircleDomain(domains[0]), .values = values };
        } else try core.fri.multidomain_insertion.insertCircleBatch(
            a,
            current_values[track],
            current_domain,
            batches[height_count - 1][track],
            domains[height_count - 1],
            last_alpha,
        );
        terminals[track] = try terminal(a, last.domain, last.values, profile.terminalLength());
    }
    for (terminals, 0..) |coefficients, track| cascade.mixTerminal(&staged, track, coefficients);
    const raw = try core.queries.drawQueries(&staged, a, source_profile.largest_log_size, input.n_queries);
    const source_wire = try source.encodeOpenings(a, raw);
    const line_openings = try a.alloc([2]cascade.LineOpening, line_count);
    for (0..line_count) |i| {
        const height = i + 1;
        const rows = try a.alloc(usize, input.n_queries * 2);
        for (raw, 0..) |position, query| {
            const base = sparse.pairBase(position, height);
            rows[query * 2] = base;
            rows[query * 2 + 1] = base + 1;
        }
        for (0..2) |track| {
            const decommitment = try trees[i][track].decommit(a, rows, &columns_by_line[i][track]);
            line_openings[i][track] = .{
                .root = trees[i][track].root(),
                .queried_coordinates = .{
                    decommitment.queried_values[0], decommitment.queried_values[1],
                    decommitment.queried_values[2], decommitment.queried_values[3],
                },
                .hash_witness = decommitment.decommitment.decommitment.hash_witness,
            };
        }
    }
    channel.* = staged;
    return .{ .arena = arena, .proof = .{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .claims = claims,
        .source_wire = source_wire,
        .line_openings = line_openings,
        .terminals = terminals,
    } };
}

pub fn proveForS31Statement(allocator: std.mem.Allocator, input: Input, channel: *Channel, binding: s31_prelude.Binding) !OwnedProof {
    var staged = channel.*;
    s31_prelude.mix(&staged, binding);
    const proof = try prove(allocator, input, &staged);
    channel.* = staged;
    return proof;
}
