//! Experimental CAS07 paired FRI over XDM05 sparse source heights, including
//! H=1 and absent insertion levels. This is never admitted by production PCS.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const utils = @import("../utils.zig");
const queries = @import("../queries.zig");
const blake2s_channel = @import("../channel/blake2s.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const xdm = @import("transposed_merkle_sparse_heights_experimental.zig");
const paired = @import("transposed_paired_sparse_heights_experimental.zig");
const old = @import("paired_cascade_experimental.zig");
const s31_prelude = @import("s31_cas05_prelude_experimental.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Channel = blake2s_channel.Blake2sChannel;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const TRANSCRIPT_TAG: u64 = 0x5333_3143_4153_3037; // S31CAS07
const PROFILE_TAG: u64 = 0x5333_3150_5246_3037; // S31PRF07
const SOURCE_ROOT_TAG: u64 = 0x5333_3153_5243_3037; // S31SRC07
const CLAIM_GROUP_TAG: u64 = 0x5333_3143_4c4d_3037; // S31CLM07
const CLAIM_HEIGHT_TAG: u64 = 0x5333_3148_5443_3037; // S31HTC07
const LINE_ROOT_TAG: u64 = 0x5333_314c_494e_3037; // S31LIN07
const TERMINAL_TAG: u64 = 0x5333_3154_524d_3037; // S31TRM07
pub const OUTER_VERSION: u16 = 7;

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

pub fn bindVersion(channel: *Channel) void {
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64(OUTER_VERSION);
    channel.mixU64(xdm.VERSION);
}

/// CAS07 transcript fields are typed before their bytes are absorbed.
/// The old transcript sent a root and two QM31 values through the same
/// `digest || 32 bytes` hash input. These distinct tags make those role
/// inputs distinct unless the underlying hash itself collides.
pub fn drawOodPoint(channel: *Channel, profile: Profile, root: xdm.Hash) !circle.CirclePointQM31 {
    try profile.validate();
    var staged = channel.*;
    staged.mixU64(PROFILE_TAG);
    staged.mixU64(profile.source.largest_log_size);
    staged.mixU64(profile.source.height_count);
    staged.mixU64(profile.log_blowup);
    staged.mixU64(profile.source.query_count);
    for (profile.source.columns[0..profile.source.height_count]) |count|
        staged.mixU64(count);
    staged.mixU64(SOURCE_ROOT_TAG);
    blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, root);
    const point = try circle.secureFieldPointFromRandomSeedChecked(staged.drawSecureFelt());
    if (point.y.c1.isZero()) return error.DegenerateOodPoint;
    channel.* = staged;
    return point;
}

/// For validated CAS07 proofs, only 3- and 6-QM31 claim absorptions have
/// the same input length as a line leaf or parent. Reject the digest prefix
/// needed for an identical BLAKE2s preimage in either case.
pub fn checkClaimInputSeparation(digest: [32]u8, felt_count: usize) !void {
    if ((felt_count == 3 and std.mem.eql(u8, digest[0..], blake2_merkle.LEAF_PREFIX[0..32])) or
        (felt_count == 6 and std.mem.eql(u8, digest[0..], blake2_merkle.NODE_PREFIX[0..32])))
        return error.TranscriptMerkleDomainOverlap;
}

pub fn drawBatchAfterOod(channel: *Channel, claims: []const []const QM31) !QM31 {
    var staged = channel.*;
    staged.mixU64(CLAIM_GROUP_TAG);
    for (claims, 0..) |height, index| {
        staged.mixU64(CLAIM_HEIGHT_TAG);
        staged.mixU64(index);
        staged.mixU64(height.len);
        try checkClaimInputSeparation(staged.digestBytes(), height.len);
        staged.mixFelts(height);
    }
    const batch = staged.drawSecureFelt();
    channel.* = staged;
    return batch;
}

pub fn mixLineRoot(channel: *Channel, index: usize, root: xdm.Hash) void {
    channel.mixU64(LINE_ROOT_TAG);
    channel.mixU64(index);
    blake2_merkle.Blake2sMerkleChannel.mixRoot(channel, root);
}

pub fn mixTerminal(channel: *Channel, coefficients: []const QM31) void {
    channel.mixU64(TERMINAL_TAG);
    channel.mixU64(coefficients.len);
    channel.mixFelts(coefficients);
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

fn requireCanonicalM31(value: M31) !void {
    if (value.v >= m31.Modulus) return error.NonCanonicalM31;
}

fn requireCanonicalQM31(value: QM31) !void {
    for (value.toM31Array()) |coordinate| try requireCanonicalM31(coordinate);
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
    try requireCanonicalQM31(proof.sampled_point.x);
    try requireCanonicalQM31(proof.sampled_point.y);
    for (proof.claims, 0..) |claims, i| {
        if (claims.len != source.columns[i]) return error.InvalidSparseProof;
        for (claims) |claim| try requireCanonicalQM31(claim);
    }
    for (proof.line_openings) |opened| {
        for (opened.queried_coordinates) |column| {
            if (column.len != source.query_count * 2) return error.InvalidSparseProof;
            for (column) |coordinate| try requireCanonicalM31(coordinate);
        }
    }
    for (proof.terminal_ordered_coeffs) |coefficient|
        try requireCanonicalQM31(coefficient);
    try xdm.validateEncoding(proof.source_wire, source, proof.source_root);
}

pub fn verifyAgainstStatement(
    allocator: std.mem.Allocator,
    proof: Proof,
    channel: *Channel,
    statement: ExpectedStatement,
) !void {
    try statement.profile.validate();
    try validateProof(proof);
    if (!matches(statement, proof)) return error.UnexpectedSparseStatement;
    var staged = channel.*;
    bindVersion(&staged);
    const sampled = try drawOodPoint(&staged, proof.profile, proof.source_root);
    if (!sampled.eql(proof.sampled_point)) return error.UnsampledOodPoint;
    const batch = try drawBatchAfterOod(&staged, proof.claims);
    const source = proof.profile.source;
    const alphas = try allocator.alloc(QM31, source.height_count);
    defer allocator.free(alphas);
    for (alphas, 0..) |*alpha, i| {
        alpha.* = staged.drawSecureFelt();
        if (i < proof.line_openings.len)
            mixLineRoot(&staged, i, proof.line_openings[i].root);
    }
    mixTerminal(&staged, proof.terminal_ordered_coeffs);
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

/// Opt-in S31 candidate contract. The binding is trusted only when the caller
/// independently reconstructs the installed key, public ABI words, and
/// compiler-owned source-to-AIR roster. Production PCS does not call this.
pub fn verifyAgainstS31Statement(
    allocator: std.mem.Allocator,
    proof: Proof,
    channel: *Channel,
    binding: s31_prelude.Binding,
    statement: ExpectedStatement,
) !void {
    var staged = channel.*;
    s31_prelude.mix(&staged, binding);
    try verifyAgainstStatement(allocator, proof, &staged, statement);
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
