//! Diagnostic relation accounting for a physical V8 Statement source.
//!
//! The V5 50-row closure predates the public G3S1 boundary. Its domain-29
//! residual therefore includes the 412 global words that row 40 emits. This
//! replacement accounts for both the physical row-36 claim and that boundary.
//! It does not authorize a proof: a V8 roster and detached verifier must bind
//! the fixed key, the public wire-count parameter, and these claims.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const relation = @import("../air/lang/relation.zig");
const v5 = @import("segment_leaf_wrapper_cohort_closure_v5.zig");
const v5_plan = @import("air/segment_leaf_wrapper_roster_direct_v5.zig");
const v8 = @import("segment_leaf_wrapper_row36_direct_v8.zig");
const global = @import("segment_leaf_wrapper_global_statement_boundary_v6.zig");
const public_wire = @import("segment_public_wire_boundary_v2.zig");
const las2 = @import("segment_leaf_wrapper_las2_boundary_v4.zig");
const universal = @import("air/universal_challenges.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
const STATEMENT_DOMAIN = @intFromEnum(relation.Domain.recursion_statement_word);
const STATEMENT_ROW: usize = 36;

/// Recompute a V5 cohort's diagnostic residual with its row-36 claim replaced
/// by the independently generated V8 physical claim and with the verifier's
/// global Statement words charged to the same relation domain. The caller
/// still needs a complete V8 proof and detached verification before relying
/// on this result as a recursive proof.
pub fn residuals(
    base: *const v5.Claims50,
    plan: *const v5_plan.Plan,
    v2_boundary: *const public_wire.PublicWireBoundaryV2,
    las2_boundary: *const las2.BoundaryV4,
    las2_expected: las2.ExpectedPublic,
    fixed_key: *const v8.FixedKey,
    replacement: v8.Claim,
    global_boundary: *const global.BoundaryV6,
    global_expected: global.ExpectedPublic,
    relations: *const universal.UniversalRelations,
) !v5.Summary {
    try fixed_key.validate();
    const prior = try base.residuals(plan, v2_boundary, las2_boundary, las2_expected, relations);
    try validateStatementClaim(base.claims[STATEMENT_ROW], base.audits[STATEMENT_ROW]);
    try validateStatementClaim(replacement.total, replacement.audit);
    return replaceAndAddBoundary(
        prior,
        base.claims[STATEMENT_ROW],
        base.audits[STATEMENT_ROW],
        replacement,
        global_boundary,
        global_expected,
        relations,
    );
}

fn validateStatementClaim(claim: QM31, audit: DomainAudit) !void {
    if (!claim.eql(audit.total) or !audit.values[STATEMENT_DOMAIN].eql(claim) or
        audit.logical_rows == 0 or audit.event_terms == 0)
        return error.InvalidV8StatementClaim;
    for (audit.values, 0..) |value, domain| {
        if (domain != STATEMENT_DOMAIN and !value.isZero())
            return error.InvalidV8StatementClaim;
    }
}

fn replaceAndAddBoundary(
    prior: v5.Summary,
    old_claim: QM31,
    old_audit: DomainAudit,
    replacement: v8.Claim,
    global_boundary: *const global.BoundaryV6,
    global_expected: global.ExpectedPublic,
    relations: *const universal.UniversalRelations,
) !v5.Summary {
    try validateStatementClaim(old_claim, old_audit);
    try validateStatementClaim(replacement.total, replacement.audit);
    var adjusted = prior;
    adjusted.domain_totals[STATEMENT_DOMAIN] = adjusted.domain_totals[STATEMENT_DOMAIN]
        .sub(old_audit.values[STATEMENT_DOMAIN]).add(replacement.audit.values[STATEMENT_DOMAIN]);
    adjusted.framework_total = adjusted.framework_total.sub(old_claim).add(replacement.total);
    adjusted.logical_rows = try std.math.add(
        u64,
        try std.math.sub(u64, adjusted.logical_rows, old_audit.logical_rows),
        replacement.audit.logical_rows,
    );
    adjusted.event_terms = try std.math.add(
        u64,
        try std.math.sub(u64, adjusted.event_terms, old_audit.event_terms),
        replacement.audit.event_terms,
    );
    try global_boundary.addToClosure(global_expected, relations, &adjusted.domain_totals, &adjusted.framework_total);
    return adjusted;
}

test "V8 Statement closure charges the verifier-owned global boundary exactly once" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const relations = universal.UniversalRelations.dummy();
    var expected = global.ExpectedPublic{ .words = @splat(M31.zero()) };
    for (&expected.words, 0..) |*word, i|
        word.* = M31.fromCanonical(@intCast(i + 1));
    const boundary = try global.BoundaryV6.derive(expected, &relations);
    const old_claim = QM31.one();
    const new_claim = old_claim.sub(boundary.claimed_sum);
    var old_audit = DomainAudit{ .values = @splat(QM31.zero()), .total = old_claim, .logical_rows = 1024, .event_terms = 1024 };
    old_audit.values[STATEMENT_DOMAIN] = old_claim;
    var new_audit = DomainAudit{ .values = @splat(QM31.zero()), .total = new_claim, .logical_rows = 1024, .event_terms = 1024 };
    new_audit.values[STATEMENT_DOMAIN] = new_claim;
    const before = v5.Summary{
        .domain_totals = @splat(QM31.zero()),
        .framework_total = QM31.zero(),
        .logical_rows = 2048,
        .event_terms = 2048,
    };
    const replacement = v8.Claim{ .total = new_claim, .audit = new_audit };
    // Replacing row 36 without the global boundary leaves an open domain.
    try std.testing.expect(!old_claim.sub(old_claim).add(new_claim).isZero());
    const closed = try replaceAndAddBoundary(before, old_claim, old_audit, replacement, &boundary, expected, &relations);
    try std.testing.expect(closed.domain_totals[STATEMENT_DOMAIN].isZero());
    try std.testing.expect(closed.framework_total.isZero());
    try std.testing.expectEqual(@as(u64, 2048), closed.logical_rows);
    try std.testing.expectEqual(@as(u64, 2048), closed.event_terms);
    expected.words[0] = expected.words[0].add(M31.one());
    try std.testing.expectError(error.InvalidGlobalStatementBoundaryV6, replaceAndAddBoundary(before, old_claim, old_audit, replacement, &boundary, expected, &relations));
    new_audit.values[STATEMENT_DOMAIN] = QM31.zero();
    try std.testing.expectError(error.InvalidV8StatementClaim, replaceAndAddBoundary(before, old_claim, old_audit, .{ .total = new_claim, .audit = new_audit }, &boundary, boundary.expected, &relations));
}
