//! Exact 50-row direct leaf relation accounting with V2 and LAS2 boundaries.
//! It is a fail-closed diagnostic until a committed V5 proof verifies.

const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v5.zig");
const views = @import("segment_leaf_wrapper_cohort_views_v3.zig");
const rows_mod = @import("segment_leaf_wrapper_cohort_rows_v5.zig");
const provider = @import("segment_leaf_wrapper_cohort_provider_v3.zig");
const range_provider = @import("segment_leaf_wrapper_range_provider_direct_v4.zig");
const frame_provider = @import("segment_leaf_wrapper_frame_provider_direct_v4.zig");
const relation = @import("../air/lang/relation.zig");
const universal = @import("air/universal_challenges.zig");
const provider_relations = @import("air/universal_provider_relations.zig");
const boundary_mod = @import("segment_public_wire_boundary_v2.zig");
const las2_mod = @import("segment_leaf_wrapper_las2_boundary_v4.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW_COUNT: usize = plan_mod.COMPONENT_COUNT;
pub const DOMAIN_COUNT: usize = universal.RELATION_COUNT;

pub const Claims50 = struct {
    claims: [ROW_COUNT]QM31,
    audits: [ROW_COUNT]DomainAudit,
    present_mask: u64,

    pub fn fromGenerated(
        plan: *const plan_mod.Plan,
        reused: *const views.ReusedClaims,
        row34_writer: *const provider.Writer,
        row34: *const provider.Interaction,
        row35: *const range_provider.ClaimAudit,
        row4: *const frame_provider.ClaimAudit,
        rows: *const rows_mod.Claims,
        relations: *const universal.UniversalRelations,
        shared: *const provider_relations.SharedProviderRelations,
    ) !Claims50 {
        try plan.validate();
        try relations.validate();
        try shared.validateAgainst(relations);
        const reused_mask = views.REUSED_MASK & ~(@as(u64, 1) << views.REPLACED_STATEMENT_ROW);
        if (reused.present_mask != reused_mask or rows.present_mask != rows_mod.ROW_MASK or
            try row34_writer.logSize() != plan.placements[34].?.geometry.log_size or
            row34_writer.buffer.calls.len != plan.poseidon_calls.total)
            return error.DirectV5ClaimCoverageMismatch;
        var result = Claims50{
            .claims = @splat(QM31.zero()),
            .audits = @splat(emptyAudit()),
            .present_mask = reused.present_mask,
        };
        @memcpy(result.claims[0..views.BASE_ROWS], &reused.claims);
        @memcpy(result.audits[0..views.BASE_ROWS], &reused.audits);
        result.claims[4] = row4.claim;
        result.audits[4] = row4.audit;
        result.present_mask |= @as(u64, 1) << 4;
        result.claims[34] = row34.claims.total();
        var provider_audit = emptyAudit();
        provider_audit.values[@intFromEnum(relation.Domain.poseidon2)] = row34.claims.sums[0];
        provider_audit.values[@intFromEnum(relation.Domain.poseidon2_io)] = row34.claims.sums[1];
        provider_audit.total = row34.claims.total();
        provider_audit.logical_rows = row34_writer.buffer.calls.len;
        provider_audit.event_terms = try std.math.mul(usize, row34_writer.buffer.calls.len, 4);
        result.audits[34] = provider_audit;
        result.present_mask |= @as(u64, 1) << 34;
        result.claims[35] = row35.claim;
        result.audits[35] = row35.audit;
        result.present_mask |= @as(u64, 1) << 35;
        for (rows.claims, rows.audits, 0..) |claim, audit, row| {
            const bit = @as(u64, 1) << @intCast(row);
            if (rows.present_mask & bit == 0) continue;
            if (result.present_mask & bit != 0) return error.DirectV5ClaimCoverageMismatch;
            result.claims[row] = claim;
            result.audits[row] = audit;
            result.present_mask |= bit;
        }
        try result.validateRows();
        return result;
    }

    pub fn validateRows(self: *const Claims50) !void {
        if (self.present_mask != (@as(u64, 1) << ROW_COUNT) - 1)
            return error.DirectV5ClaimCoverageMismatch;
        for (self.claims, self.audits, 0..) |claim, audit, row| {
            try boundary_mod.requireCanonical(claim);
            try boundary_mod.requireCanonical(audit.total);
            const empty = audit.logical_rows == 0 and audit.event_terms == 0;
            if ((audit.logical_rows == 0) != (audit.event_terms == 0) or
                (empty and !claim.isZero()))
                return error.DirectV5AuditGeometryMismatch;
            var total = QM31.zero();
            for (audit.values, 0..) |value, domain| {
                try boundary_mod.requireCanonical(value);
                if (empty and !value.isZero()) return error.DirectV5AuditGeometryMismatch;
                if (row == 34 and domain != @intFromEnum(relation.Domain.poseidon2) and
                    domain != @intFromEnum(relation.Domain.poseidon2_io) and !value.isZero())
                    return error.DirectV5ProviderDomainMismatch;
                if (row == 35 and domain != @intFromEnum(relation.Domain.range_check_8_8) and
                    !value.isZero()) return error.DirectV5ProviderDomainMismatch;
                total = total.add(value);
            }
            if (!total.eql(audit.total) or !audit.total.eql(claim))
                return error.DirectV5ClaimMismatch;
            if (row == 10 and !claim.isZero()) return error.DirectV5ClaimMismatch;
        }
    }

    pub fn residuals(
        self: *const Claims50,
        plan: *const plan_mod.Plan,
        v2_boundary: *const boundary_mod.PublicWireBoundaryV2,
        las2: *const las2_mod.BoundaryV4,
        expected: las2_mod.ExpectedPublic,
        relations: *const universal.UniversalRelations,
    ) !Summary {
        try plan.validate();
        try self.validateRows();
        try v2_boundary.validate();
        var totals = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
        var framework_total = v2_boundary.claimed_sum;
        var logical_rows: u64 = 0;
        var event_terms: u64 = 0;
        for (self.claims, self.audits) |claim, audit| {
            framework_total = framework_total.add(claim);
            logical_rows = try std.math.add(u64, logical_rows, audit.logical_rows);
            event_terms = try std.math.add(u64, event_terms, audit.event_terms);
            for (audit.values, 0..) |value, domain| totals[domain] = totals[domain].add(value);
        }
        totals[@intFromEnum(v2_boundary.domain)] = totals[@intFromEnum(v2_boundary.domain)].add(v2_boundary.claimed_sum);
        try las2.addToClosure(expected, relations, &totals, &framework_total);
        return .{ .domain_totals = totals, .framework_total = framework_total, .logical_rows = logical_rows, .event_terms = event_terms };
    }

    pub fn verifyAllDomains(
        self: *const Claims50,
        plan: *const plan_mod.Plan,
        v2_boundary: *const boundary_mod.PublicWireBoundaryV2,
        las2: *const las2_mod.BoundaryV4,
        expected: las2_mod.ExpectedPublic,
        relations: *const universal.UniversalRelations,
    ) !Summary {
        const summary = try self.residuals(plan, v2_boundary, las2, expected, relations);
        for (summary.domain_totals) |value| if (!value.isZero())
            return error.DirectV5RelationNotClosed;
        if (!summary.framework_total.isZero()) return error.DirectV5RelationNotClosed;
        return summary;
    }
};

pub const Summary = struct {
    domain_totals: [DOMAIN_COUNT]QM31,
    framework_total: QM31,
    logical_rows: u64,
    event_terms: u64,
};

fn emptyAudit() DomainAudit {
    return .{ .values = @splat(QM31.zero()), .total = QM31.zero(), .logical_rows = 0, .event_terms = 0 };
}

test "V5 closure rejects missing local claim and unauthorized provider domain" {
    var claims = Claims50{
        .claims = @splat(QM31.zero()),
        .audits = @splat(emptyAudit()),
        .present_mask = (@as(u64, 1) << ROW_COUNT) - 1,
    };
    try claims.validateRows();
    claims.present_mask &= ~(@as(u64, 1) << 49);
    try std.testing.expectError(error.DirectV5ClaimCoverageMismatch, claims.validateRows());
    claims.present_mask |= @as(u64, 1) << 49;
    claims.audits[34].values[@intFromEnum(relation.Domain.recursion_statement_word)] = QM31.one();
    claims.audits[34].total = QM31.one();
    claims.audits[34].logical_rows = 1;
    claims.audits[34].event_terms = 4;
    claims.claims[34] = QM31.one();
    try std.testing.expectError(error.DirectV5ProviderDomainMismatch, claims.validateRows());
}
