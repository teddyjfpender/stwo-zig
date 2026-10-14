//! Experimental H1 join: four authenticated plain source roots drive separate
//! original and own-quotient circle-to-line degree checks. The statement's
//! roots, OOD point/claims, batch/fold challenges, and raw queries must be
//! verifier-owned. This module does not derive those from a transcript.
const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const utils = @import("../utils.zig");
const source = @import("four_root_pair_openings_experimental.zig");
const wire = @import("four_root_pair_wire_experimental.zig");
const dual = @import("paired_independent_h1_experimental.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const version: u16 = 11;

pub const Statement = struct {
    source: source.Expected,
    point: circle.CirclePointQM31,
    /// Exactly one verifier-owned OOD claim per committed source column in
    /// this H1 slice. Multi-mask Gate columns require a later protocol.
    claims: [source.root_count][]const QM31,
    batch_challenge: QM31,
    fold_challenge: QM31,
    log_blowup: u32,
};

pub const Proof = struct {
    protocol_version: u16 = version,
    source_wire: []const u8,
    terminals: [2][]const QM31,
};

pub fn terminalLength(statement: Statement) !usize {
    const k = statement.source.lifting_log_size;
    if (statement.log_blowup == 0 or k <= statement.log_blowup or
        k >= @bitSizeOf(usize)) return error.InvalidFourRootH1Profile;
    return @as(usize, 1) << @intCast(k - statement.log_blowup - 1);
}

pub fn verify(
    allocator: std.mem.Allocator,
    statement: Statement,
    proof: Proof,
) !void {
    if (proof.protocol_version != version) return error.UnsupportedFourRootH1Version;
    const k = statement.source.lifting_log_size;
    const bound = try terminalLength(statement);
    if (proof.terminals[0].len != bound or proof.terminals[1].len != bound)
        return error.InvalidFourRootH1Profile;
    for (proof.terminals) |coefficients| for (coefficients) |coefficient| {
        for (coefficient.toM31Array()) |word| {
            if (word.v >= m31.Modulus) return error.NonCanonicalTerminal;
        }
    };
    var column_count: usize = 0;
    for (statement.source.column_log_sizes, statement.claims) |logs, claims| {
        if (logs.len == 0 or logs.len != claims.len)
            return error.InvalidFourRootH1Profile;
        for (logs) |log| {
            if (log != k) return error.UnsupportedFourRootH1Height;
        }
        column_count = std.math.add(usize, column_count, logs.len) catch
            return error.InvalidFourRootH1Profile;
    }
    const flat_claims = try allocator.alloc(QM31, column_count);
    defer allocator.free(flat_claims);
    var claim_at: usize = 0;
    for (statement.claims) |claims| {
        @memcpy(flat_claims[claim_at..][0..claims.len], claims);
        claim_at += claims.len;
    }
    var authenticated = try wire.verifyAndCollect(allocator, proof.source_wire, statement.source);
    defer authenticated.deinit();
    var context = try dual.RowContext.init(allocator, statement.point, flat_claims, statement.batch_challenge);
    defer context.deinit();
    const domain = canonic.CanonicCoset.new(k).circleDomain();
    const line_domain = line.LineDomain.fromCircleDomain(domain);
    var polys: [2]line.LinePoly = undefined;
    var polys_built: usize = 0;
    defer for (polys[0..polys_built]) |*poly| poly.deinit(allocator);
    for (proof.terminals, &polys) |coefficients, *poly| {
        const owned = try allocator.dupe(QM31, coefficients);
        poly.* = line.LinePoly.fromOrderedCoefficients(owned);
        polys_built += 1;
    }
    const row_values = try allocator.alloc(M31, column_count);
    defer allocator.free(row_values);
    for (statement.source.raw_queries, 0..) |raw, query| {
        const pair_start = raw & ~@as(usize, 1);
        var pair_words: [2][2]QM31 = undefined;
        for (0..2) |side| {
            const row = pair_start + side;
            const p = domain.at(utils.bitReverseIndex(row, k));
            var at: usize = 0;
            for (authenticated.openings) |opening| {
                for (opening.queried_values) |column| {
                    row_values[at] = column[2 * query + side];
                    at += 1;
                }
            }
            if (at != column_count) return error.InvalidFourRootH1Profile;
            pair_words[side] = try context.openedValues(row_values, p);
        }
        const p0 = domain.at(utils.bitReverseIndex(pair_start, k));
        const x = line_domain.at(utils.bitReverseIndex(raw >> 1, k - 1));
        for (0..2) |track| {
            const folded = pair_words[0][track].add(pair_words[1][track])
                .add(statement.fold_challenge.mul(pair_words[0][track]
                .sub(pair_words[1][track]).mulM31(try p0.y.inv())));
            const terminal = try polys[track].evalAtPoint(allocator, QM31.fromBase(x));
            if (!folded.eql(terminal))
                return if (track == 0) error.OriginalDegreeFoldMismatch else error.QuotientDegreeFoldMismatch;
        }
    }
}
