//! Experimental generic adjacent-height paired FRI relation checker. The
//! three-height fixture uses one XDM03 source root. S31CAS04 is the canonical
//! experimental outer wire; neither API is an admitted production PCS proof.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const utils = @import("../utils.zig");
const queries = @import("../queries.zig");
const blake2_hash = @import("../vcs/blake2_hash.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const xdm = @import("transposed_merkle_cascade.zig");
const paired_answers = @import("transposed_paired_cascade.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Hash = xdm.Hash;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const TRANSCRIPT_TAG: u64 = 0x5333_3143_4153_3034; // S31CAS04
pub const OUTER_VERSION: u16 = 4;
const ROOT_TAG: u64 = 0x5333_3143_4152_3033;
const CLAIM_TAG: u64 = 0x5333_3143_4143_3033;

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
    source_root: Hash,
    claims: []const []const QM31,
};

pub const LineOpening = struct {
    root: Hash,
    queried_coordinates: [4][]const M31,
    hash_witness: []Hash,
};

pub const Proof = struct {
    profile: Profile,
    source_root: Hash,
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

pub fn drawOodPoint(channel: anytype, profile: Profile, root: Hash) !circle.CirclePointQM31 {
    try profile.validate();
    var staged = channel.*;
    staged.mixU64(ROOT_TAG);
    staged.mixU64(profile.source.largest_log_size);
    staged.mixU64(profile.source.height_count);
    staged.mixU64(profile.log_blowup);
    staged.mixU64(profile.source.query_count);
    for (profile.source.columns[0..profile.source.height_count]) |count|
        staged.mixU64(count);
    staged.updateDigest(blake2_hash.Blake2sHasher.concatAndHash(staged.digestBytes(), root));
    const point = try circle.secureFieldPointFromRandomSeedChecked(staged.drawSecureFelt());
    if (point.y.c1.isZero()) return error.DegenerateOodPoint;
    channel.* = staged;
    return point;
}

pub fn drawBatchAfterOod(channel: anytype, claims: []const []const QM31) QM31 {
    channel.mixU64(CLAIM_TAG);
    for (claims) |height| channel.mixFelts(height);
    return channel.drawSecureFelt();
}

fn matches(statement: ExpectedStatement, proof: Proof) bool {
    if (!std.meta.eql(statement.profile, proof.profile) or
        !std.mem.eql(u8, &statement.source_root, &proof.source_root) or
        statement.claims.len != proof.claims.len) return false;
    for (statement.claims, proof.claims) |expected_height, actual_height| {
        if (expected_height.len != actual_height.len) return false;
        for (expected_height, actual_height) |expected, actual|
            if (!expected.eql(actual)) {
                return false;
            };
    }
    return true;
}

/// Structural checks only. Authentication remains exclusive to the complete
/// statement-bound verifier and cannot be inferred from this function.
pub fn validateProof(proof: Proof) !void {
    try proof.profile.validate();
    const source = proof.profile.source;
    if (proof.claims.len != source.height_count or
        proof.line_openings.len != source.height_count - 1 or
        proof.terminal_ordered_coeffs.len != proof.profile.terminalLength())
        return error.InvalidCascadeProof;
    for (proof.claims, 0..) |claims, i| {
        if (claims.len != source.columns[i]) return error.InvalidCascadeProof;
    }
    for (proof.line_openings, 0..) |opened, i| {
        const width = source.width(i + 1);
        for (opened.queried_coordinates) |column| {
            if (column.len != source.query_count * width) return error.InvalidCascadeProof;
        }
    }
    try xdm.validateEncoding(proof.source_wire, source, proof.source_root);
}

/// Complete statement-bound verifier for the in-memory experimental harness.
/// It never receives caller-supplied paired answer slices; XDM authentication
/// runs internally and the caller's transcript changes only after success.
pub fn verifyAgainstStatement(
    allocator: std.mem.Allocator,
    proof: Proof,
    channel: anytype,
    statement: ExpectedStatement,
) !void {
    try statement.profile.validate();
    try validateProof(proof);
    if (!matches(statement, proof)) return error.UnexpectedCascadeStatement;
    var staged = channel.*;
    bindVersion(&staged);
    const sampled = try drawOodPoint(&staged, proof.profile, proof.source_root);
    if (!sampled.eql(proof.sampled_point)) return error.UnsampledOodPoint;
    const batch = drawBatchAfterOod(&staged, proof.claims);
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
    var answers = try paired_answers.fromVerifiedOpenings(
        allocator,
        opened,
        raw,
        sampled,
        proof.claims,
        batch,
    );
    defer answers.deinit();
    try verifyFoldCascade(allocator, proof, raw, answers.values, alphas);
    channel.* = staged;
}

/// Experimental scalar insertion shared by every height. Native butterflies
/// omit the published 1/2 factors. Dividing layer i by 2^i makes the inserted
/// height-i batch carry an extra 2^-i factor; see PAIRED_CASCADE_DESIGN.md.
pub fn foldInsertedPair(
    previous_even: QM31,
    previous_odd: QM31,
    line_x: M31,
    inserted_even: QM31,
    inserted_odd: QM31,
    circle_y: M31,
    alpha: QM31,
) !QM31 {
    const previous = try foldPair(previous_even, previous_odd, line_x, alpha);
    const inserted = try foldPair(inserted_even, inserted_odd, circle_y, alpha);
    return previous.add(alpha.square().mul(inserted));
}

fn lineWord(opening: LineOpening, at: usize) QM31 {
    return QM31.fromM31Array(.{
        opening.queried_coordinates[0][at], opening.queried_coordinates[1][at],
        opening.queried_coordinates[2][at], opening.queried_coordinates[3][at],
    });
}

fn verifyFoldCascade(
    allocator: std.mem.Allocator,
    proof: Proof,
    raw: []const usize,
    answers: []const []QM31,
    alphas: []const QM31,
) !void {
    const source = proof.profile.source;
    const k = source.largest_log_size;
    const positions = try allocator.alloc([]usize, proof.line_openings.len);
    defer allocator.free(positions);
    var built: usize = 0;
    defer for (positions[0..built]) |row| allocator.free(row);
    for (proof.line_openings, 0..) |opening, i| {
        const height = i + 1;
        const width = source.width(height);
        const line_log = k - @as(u32, @intCast(height));
        const line_domain = line.LineDomain.fromCircleDomain(
            canonic.CanonicCoset.new(line_log + 1).circleDomain(),
        );
        const rows = try allocator.alloc(usize, raw.len * width);
        positions[i] = rows;
        built += 1;
        for (raw, 0..) |position, query| {
            const base = (position & ~(source.width(0) - 1)) >> @intCast(height);
            for (0..width) |j| rows[query * width + j] = base + j;
        }
        var verifier = try vcs_verifier.MerkleVerifierLifted(Hasher).init(
            allocator,
            opening.root,
            &[_]u32{line_domain.logSize()} ** 4,
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
    for (raw, 0..) |position, query| {
        const base = position & ~(source.width(0) - 1);
        var projected_point = canonic.CanonicCoset.new(k).circleDomain()
            .at(utils.bitReverseIndex(position, k));
        for (1..source.height_count) |height| {
            projected_point = projected_point.double();
            const source_log = k - @as(u32, @intCast(height));
            const projected_row = ((position >> @intCast(height + 1)) << 1) | (position & 1);
            const expected_point = canonic.CanonicCoset.new(source_log).circleDomain()
                .at(utils.bitReverseIndex(projected_row, source_log));
            if (!projected_point.eql(expected_point)) return error.InvalidQueryProjection;
        }
        for (0..source.height_count) |step| {
            const output_width = source.width(step) / 2;
            const source_base = query * source.width(step);
            for (0..output_width) |j| {
                const source_row = (base >> @intCast(step)) + 2 * j;
                const circle_log = k - @as(u32, @intCast(step));
                const circle_y = canonic.CanonicCoset.new(circle_log).circleDomain()
                    .at(utils.bitReverseIndex(source_row, circle_log)).y;
                const inserted_even = answers[step][source_base + 2 * j];
                const inserted_odd = answers[step][source_base + 2 * j + 1];
                const value = if (step == 0)
                    try foldPair(inserted_even, inserted_odd, circle_y, alphas[step])
                else blk: {
                    const previous_width = source.width(step);
                    const previous_base = query * previous_width;
                    const prior = proof.line_openings[step - 1];
                    const line_row = (base >> @intCast(step)) + 2 * j;
                    const line_log = circle_log;
                    const line_domain = line.LineDomain.fromCircleDomain(
                        canonic.CanonicCoset.new(line_log + 1).circleDomain(),
                    );
                    const x = line_domain.at(utils.bitReverseIndex(line_row, line_log));
                    break :blk try foldInsertedPair(
                        lineWord(prior, previous_base + 2 * j),
                        lineWord(prior, previous_base + 2 * j + 1),
                        x,
                        inserted_even,
                        inserted_odd,
                        circle_y,
                        alphas[step],
                    );
                };
                if (step + 1 < source.height_count) {
                    const next_width = source.width(step + 1);
                    const next = proof.line_openings[step];
                    if (!value.eql(lineWord(next, query * next_width + j)))
                        return error.IntermediateFoldMismatch;
                } else {
                    const terminal_row = base >> @intCast(source.height_count);
                    const terminal_x = terminal_domain.at(utils.bitReverseIndex(
                        terminal_row,
                        terminal_domain.logSize(),
                    ));
                    const expected = try terminal_poly.evalAtPoint(
                        allocator,
                        QM31.fromBase(terminal_x),
                    );
                    if (!value.eql(expected)) return error.TerminalFoldMismatch;
                }
            }
        }
    }
}

fn foldPair(even: QM31, odd: QM31, coordinate: M31, alpha: QM31) !QM31 {
    return even.add(odd).add(alpha.mul(even.sub(odd).mulM31(try coordinate.inv())));
}
