//! Experimental one-height, two-track FRI. The original and each original's
//! own two-point quotient are batched separately, then each receives its own
//! terminal degree check. This is not a production PCS or a soundness profile.

const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const m31 = @import("../fields/m31.zig");
const cm31 = @import("../fields/cm31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const utils = @import("../utils.zig");
const queries = @import("../queries.zig");
const channel_mod = @import("../channel/blake2s.zig");
const xdm = @import("transposed_merkle_sparse_heights_experimental.zig");
const cas07 = @import("paired_sparse_cascade_heights_experimental.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CM31 = cm31.CM31;
const Channel = channel_mod.Blake2sChannel;
pub const VERSION: u16 = 8;
const MODE_TAG: u64 = 0x5333_3144_5541_4c38; // S31DUAL8
const ORIGINAL_TERMINAL_TAG: u64 = 0x5333_314f_5247_3038; // S31ORG08
const QUOTIENT_TERMINAL_TAG: u64 = 0x5333_3151_4f54_3038; // S31QOT08

pub const Profile = cas07.Profile;
pub const ExpectedStatement = cas07.ExpectedStatement;
pub const Proof = struct {
    version: u16 = VERSION,
    profile: Profile,
    source_root: xdm.Hash,
    sampled_point: circle.CirclePointQM31,
    claims: []const []const QM31,
    source_wire: []const u8,
    original_terminal: []const QM31,
    quotient_terminal: []const QM31,
};

pub fn validateProfile(profile: Profile) !void {
    try profile.validate();
    if (profile.source.height_count != 1) return error.UnsupportedDualHeight;
}

pub fn bindVersion(channel: *Channel) void {
    channel.mixU64(MODE_TAG);
    channel.mixU64(VERSION);
    channel.mixU64(xdm.VERSION);
}

pub fn mixTerminals(channel: *Channel, original: []const QM31, quotient: []const QM31) void {
    channel.mixU64(ORIGINAL_TERMINAL_TAG);
    channel.mixU64(original.len);
    channel.mixFelts(original);
    channel.mixU64(QUOTIENT_TERMINAL_TAG);
    channel.mixU64(quotient.len);
    channel.mixFelts(quotient);
}

/// This context keeps the two-point line coefficients and independent batch
/// powers once per column, rather than rebuilding them for every domain row.
pub const RowContext = struct {
    allocator: std.mem.Allocator,
    coefficients: []constraints.LineCoeffs,
    powers: []QM31,
    point: circle.CirclePointQM31,

    pub fn init(allocator: std.mem.Allocator, point: circle.CirclePointQM31, claims: []const QM31, batch: QM31) !RowContext {
        const coefficients = try allocator.alloc(constraints.LineCoeffs, claims.len);
        errdefer allocator.free(coefficients);
        const powers = try allocator.alloc(QM31, claims.len);
        errdefer allocator.free(powers);
        var power = QM31.one();
        for (claims, coefficients, powers) |claim, *coefficient, *slot| {
            coefficient.* = try constraints.complexConjugateLineCoeffs(point, claim, QM31.one());
            slot.* = power;
            power = power.mul(batch);
        }
        return .{ .allocator = allocator, .coefficients = coefficients, .powers = powers, .point = point };
    }

    pub fn deinit(self: *RowContext) void {
        self.allocator.free(self.coefficients);
        self.allocator.free(self.powers);
        self.* = undefined;
    }

    fn inverseDivisor(self: RowContext, p: circle.CirclePointM31) !CM31 {
        const denominator = self.point.x.c0.sub(CM31.fromBase(p.x)).mul(self.point.y.c1)
            .sub(self.point.y.c0.sub(CM31.fromBase(p.y)).mul(self.point.x.c1));
        return denominator.inv();
    }

    fn add(self: RowContext, result: *[2]QM31, column: usize, value: M31, y: M31, inverse: CM31) void {
        const coefficient = self.coefficients[column];
        const quotient = coefficient.c.mulM31(value)
            .sub(coefficient.a.mulM31(y)).sub(coefficient.b).mulCM31(inverse);
        result[0] = result[0].add(self.powers[column].mul(QM31.fromBase(value)));
        result[1] = result[1].add(self.powers[column].mul(quotient));
    }

    pub fn dense(self: RowContext, columns: []const []const M31, row: usize, p: circle.CirclePointM31) ![2]QM31 {
        if (columns.len != self.coefficients.len) return error.InvalidDualShape;
        const inverse = try self.inverseDivisor(p);
        var result = [2]QM31{ QM31.zero(), QM31.zero() };
        for (columns, 0..) |column, index| {
            if (row >= column.len) return error.InvalidDualShape;
            self.add(&result, index, column[row], p.y, inverse);
        }
        return result;
    }

    pub fn opened(self: RowContext, rows: xdm.VerifiedOpenings, query: usize, side: usize, p: circle.CirclePointM31) ![2]QM31 {
        if (self.coefficients.len != rows.profile.columns[0]) return error.InvalidDualShape;
        const inverse = try self.inverseDivisor(p);
        var result = [2]QM31{ QM31.zero(), QM31.zero() };
        for (0..self.coefficients.len) |index|
            self.add(&result, index, rows.at(0, query, side, index), p.y, inverse);
        return result;
    }
};

fn matches(statement: ExpectedStatement, proof: Proof) bool {
    if (!std.meta.eql(statement.profile, proof.profile) or
        !std.mem.eql(u8, &statement.source_root, &proof.source_root) or
        statement.claims.len != 1 or proof.claims.len != 1 or
        statement.claims[0].len != proof.claims[0].len) return false;
    for (statement.claims[0], proof.claims[0]) |expected, actual|
        if (!expected.eql(actual)) return false;
    return true;
}

fn canonical(value: QM31) bool {
    for (value.toM31Array()) |word| if (word.v >= m31.Modulus) return false;
    return true;
}

/// Canonical/shape validation only. It does not authenticate the source root.
pub fn validateProof(proof: Proof) !void {
    try validateProfile(proof.profile);
    if (proof.version != VERSION) return error.UnsupportedDualVersion;
    if (proof.claims.len != 1 or proof.claims[0].len != proof.profile.source.columns[0] or
        proof.original_terminal.len != proof.profile.terminalLength() or
        proof.quotient_terminal.len != proof.profile.terminalLength() or
        !canonical(proof.sampled_point.x) or !canonical(proof.sampled_point.y))
        return error.InvalidDualProof;
    for (proof.claims[0]) |claim| if (!canonical(claim)) return error.InvalidDualProof;
    for (proof.original_terminal) |word| if (!canonical(word)) return error.InvalidDualProof;
    for (proof.quotient_terminal) |word| if (!canonical(word)) return error.InvalidDualProof;
    try xdm.validateEncoding(proof.source_wire, proof.profile.source, proof.source_root);
}

pub fn verifyAgainstStatement(allocator: std.mem.Allocator, proof: Proof, channel: *Channel, statement: ExpectedStatement) !void {
    try validateProfile(statement.profile);
    try validateProof(proof);
    if (!matches(statement, proof)) return error.UnexpectedDualStatement;

    var staged = channel.*;
    bindVersion(&staged);
    const point = try cas07.drawOodPoint(&staged, proof.profile, proof.source_root);
    if (!point.eql(proof.sampled_point)) return error.UnsampledOodPoint;
    const batch = try cas07.drawBatchAfterOod(&staged, proof.claims);
    const alpha = staged.drawSecureFelt();
    mixTerminals(&staged, proof.original_terminal, proof.quotient_terminal);
    const raw = try queries.drawQueries(&staged, allocator, proof.profile.source.largest_log_size, proof.profile.source.query_count);
    defer allocator.free(raw);
    var opened = try xdm.verifyAndCollect(allocator, proof.source_wire, proof.profile.source, proof.source_root, raw);
    defer opened.deinit();
    var context = try RowContext.init(allocator, point, proof.claims[0], batch);
    defer context.deinit();
    const k = proof.profile.source.largest_log_size;
    const domain = canonic.CanonicCoset.new(k).circleDomain();
    const line_domain = line.LineDomain.fromCircleDomain(domain);
    const original_coeffs = try allocator.dupe(QM31, proof.original_terminal);
    var original_poly = line.LinePoly.fromOrderedCoefficients(original_coeffs);
    defer original_poly.deinit(allocator);
    const quotient_coeffs = try allocator.dupe(QM31, proof.quotient_terminal);
    var quotient_poly = line.LinePoly.fromOrderedCoefficients(quotient_coeffs);
    defer quotient_poly.deinit(allocator);
    for (raw, 0..) |position, query| {
        const base = xdm.pairBase(position, 0);
        const p0 = domain.at(utils.bitReverseIndex(base, k));
        const p1 = domain.at(utils.bitReverseIndex(base + 1, k));
        const first = try context.opened(opened, query, 0, p0);
        const second = try context.opened(opened, query, 1, p1);
        const x = line_domain.at(utils.bitReverseIndex(position >> 1, k - 1));
        const expected = [2]QM31{
            try original_poly.evalAtPoint(allocator, QM31.fromBase(x)),
            try quotient_poly.evalAtPoint(allocator, QM31.fromBase(x)),
        };
        for (0..2) |track| {
            const folded = first[track].add(second[track])
                .add(alpha.mul(first[track].sub(second[track]).mulM31(try p0.y.inv())));
            if (!folded.eql(expected[track]))
                return if (track == 0) error.OriginalDegreeFoldMismatch else error.QuotientDegreeFoldMismatch;
        }
    }
    channel.* = staged;
}
