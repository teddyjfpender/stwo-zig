//! Experimental CAS05 sparse per-layer paired FRI checker. The source tree
//! opens two rows per height and line trees open two rows per fold layer.
//! This is never admitted by production PCS.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const utils = @import("../utils.zig");
const queries = @import("../queries.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const xdm = @import("transposed_merkle_sparse.zig");
const paired = @import("transposed_paired_sparse.zig");
const old = @import("paired_cascade_experimental.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const TRANSCRIPT_TAG: u64 = 0x5333_3143_4153_3035; // S31CAS05
pub const OUTER_VERSION: u16 = 5;

pub const Profile = struct {
    source: xdm.Profile,
    log_blowup: u32,

    pub fn validate(self: Profile) !void {
        try self.source.validate();
        if (self.log_blowup == 0 or
            self.source.largest_log_size < self.source.height_count + self.log_blowup)
            return error.InvalidCascadeProfile;
    }

    pub fn terminalLength(self: Profile) usize {
        return @as(usize, 1) << @intCast(
            self.source.largest_log_size - @as(u32, @intCast(self.source.height_count)) - self.log_blowup,
        );
    }
};
pub const ExpectedStatement = struct {
    profile: Profile,
    source_root: xdm.Hash,
    claims: []const []const QM31,
};
pub const LineOpening = old.LineOpening;
pub const Proof = struct {
    profile: Profile,
    source_root: xdm.Hash,
    sampled_point: circle.CirclePointQM31,
    claims: []const []const QM31,
    source_wire: []const u8,
    line_openings: []const LineOpening,
    terminal_ordered_coeffs: []const QM31,
};

pub fn bindVersion(channel: anytype) void {
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64(OUTER_VERSION);
    channel.mixU64(xdm.VERSION);
}

fn matches(statement: ExpectedStatement, proof: Proof) bool {
    if (!std.meta.eql(statement.profile, proof.profile) or
        !std.mem.eql(u8, &statement.source_root, &proof.source_root) or
        statement.claims.len != proof.claims.len) return false;
    for (statement.claims, proof.claims) |expected_height, actual_height| {
        if (expected_height.len != actual_height.len) return false;
        for (expected_height, actual_height) |expected, actual|
            if (!expected.eql(actual)) return false;
    }
    return true;
}

/// Structural/canonical check only; authentication happens in the complete
/// statement-bound verifier and cannot be inferred from this function.
pub fn validateProof(proof: Proof) !void {
    try proof.profile.validate();
    const source = proof.profile.source;
    if (proof.claims.len != source.height_count or
        proof.line_openings.len != source.height_count - 1 or
        proof.terminal_ordered_coeffs.len != proof.profile.terminalLength())
        return error.InvalidSparseProof;
    for (proof.claims, 0..) |claims, i|
        if (claims.len != source.columns[i]) return error.InvalidSparseProof;
    for (proof.line_openings) |opened|
        for (opened.queried_coordinates) |column|
            if (column.len != source.query_count * 2) return error.InvalidSparseProof;
    try xdm.validateEncoding(proof.source_wire, source, proof.source_root);
}

pub fn verifyAgainstStatement(
    allocator: std.mem.Allocator,
    proof: Proof,
    channel: anytype,
    statement: ExpectedStatement,
) !void {
    try statement.profile.validate();
    try validateProof(proof);
    if (!matches(statement, proof)) return error.UnexpectedSparseStatement;
    var staged = channel.*;
    bindVersion(&staged);
    const sampled = try old.drawOodPoint(&staged, proof.profile, proof.source_root);
    if (!sampled.eql(proof.sampled_point)) return error.UnsampledOodPoint;
    const batch = old.drawBatchAfterOod(&staged, proof.claims);
    const source = proof.profile.source;
    const alphas = try allocator.alloc(QM31, source.height_count);
    defer allocator.free(alphas);
    for (alphas, 0..) |*alpha, i| {
        alpha.* = staged.drawSecureFelt();
        if (i < proof.line_openings.len)
            blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, proof.line_openings[i].root);
    }
    staged.mixFelts(proof.terminal_ordered_coeffs);
    const raw = try queries.drawQueries(
        &staged,
        allocator,
        source.largest_log_size,
        source.query_count,
    );
    defer allocator.free(raw);
    var opened = try xdm.verifyAndCollect(
        allocator,
        proof.source_wire,
        source,
        proof.source_root,
        raw,
    );
    defer opened.deinit();
    var answers = try paired.fromVerifiedOpenings(
        allocator,
        opened,
        raw,
        sampled,
        proof.claims,
        batch,
    );
    defer answers.deinit();
    try verifyFolds(allocator, proof, raw, answers.values, alphas);
    channel.* = staged;
}

fn lineWord(opening: LineOpening, at: usize) QM31 {
    return QM31.fromM31Array(.{
        opening.queried_coordinates[0][at], opening.queried_coordinates[1][at],
        opening.queried_coordinates[2][at], opening.queried_coordinates[3][at],
    });
}

fn foldPair(even: QM31, odd: QM31, coordinate: M31, alpha: QM31) !QM31 {
    return even.add(odd).add(alpha.mul(even.sub(odd).mulM31(try coordinate.inv())));
}

fn verifyFolds(
    allocator: std.mem.Allocator,
    proof: Proof,
    raw: []const usize,
    answers: []const []QM31,
    alphas: []const QM31,
) !void {
    const source = proof.profile.source;
    const k = source.largest_log_size;
    // Each committed line opens only the pair needed at the next fold.
    for (proof.line_openings, 0..) |opening, i| {
        const height = i + 1;
        const line_log = k - @as(u32, @intCast(height));
        const domain = line.LineDomain.fromCircleDomain(
            canonic.CanonicCoset.new(line_log + 1).circleDomain(),
        );
        const rows = try allocator.alloc(usize, raw.len * 2);
        defer allocator.free(rows);
        for (raw, 0..) |position, query| {
            const base = xdm.pairBase(position, height);
            rows[query * 2] = base;
            rows[query * 2 + 1] = base + 1;
        }
        var verifier = try vcs_verifier.MerkleVerifierLifted(Hasher).init(
            allocator,
            opening.root,
            &[_]u32{domain.logSize()} ** 4,
        );
        defer verifier.deinit(allocator);
        const columns = opening.queried_coordinates;
        try verifier.verify(allocator, rows, &columns, .{ .hash_witness = opening.hash_witness });
    }
    const terminal_coeffs = try allocator.dupe(QM31, proof.terminal_ordered_coeffs);
    var terminal_poly = line.LinePoly.fromOrderedCoefficients(terminal_coeffs);
    defer terminal_poly.deinit(allocator);
    const terminal_domain = line.LineDomain.fromCircleDomain(
        canonic.CanonicCoset.new(k - @as(u32, @intCast(source.height_count - 1))).circleDomain(),
    );
    const first_domain = canonic.CanonicCoset.new(k).circleDomain();
    for (raw, 0..) |position, query| {
        var projected = first_domain.at(utils.bitReverseIndex(position, k));
        for (1..source.height_count) |height| {
            projected = projected.double();
            const source_log = k - @as(u32, @intCast(height));
            const circle_row = xdm.pairBase(position, height) | (position & 1);
            const expected = canonic.CanonicCoset.new(source_log).circleDomain()
                .at(utils.bitReverseIndex(circle_row, source_log));
            if (!projected.eql(expected)) return error.InvalidQueryProjection;
        }
        for (0..source.height_count) |step| {
            const base = xdm.pairBase(position, step);
            const circle_log = k - @as(u32, @intCast(step));
            const circle_y = canonic.CanonicCoset.new(circle_log).circleDomain()
                .at(utils.bitReverseIndex(base, circle_log)).y;
            const inserted_even = answers[step][query * 2];
            const inserted_odd = answers[step][query * 2 + 1];
            const folded = if (step == 0)
                try foldPair(inserted_even, inserted_odd, circle_y, alphas[step])
            else blk: {
                const previous = proof.line_openings[step - 1];
                const line_domain = line.LineDomain.fromCircleDomain(
                    canonic.CanonicCoset.new(circle_log + 1).circleDomain(),
                );
                const x = line_domain.at(utils.bitReverseIndex(base, circle_log));
                break :blk try old.foldInsertedPair(
                    lineWord(previous, query * 2),
                    lineWord(previous, query * 2 + 1),
                    x,
                    inserted_even,
                    inserted_odd,
                    circle_y,
                    alphas[step],
                );
            };
            if (step + 1 < source.height_count) {
                const selected = (position >> @intCast(step + 1)) & 1;
                const next = proof.line_openings[step];
                if (!folded.eql(lineWord(next, query * 2 + selected)))
                    return error.IntermediateFoldMismatch;
            } else {
                const row = position >> @intCast(source.height_count);
                const x = terminal_domain.at(utils.bitReverseIndex(row, terminal_domain.logSize()));
                const expected = try terminal_poly.evalAtPoint(allocator, QM31.fromBase(x));
                if (!folded.eql(expected)) return error.TerminalFoldMismatch;
            }
        }
    }
}
