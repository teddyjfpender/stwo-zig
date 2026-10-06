//! Whole-cohort interaction accounting for the direct 47-row leaf wrapper.
//!
//! The inputs are the actual generated V2, row34 and appended-row witnesses.
//! This is a diagnostic before a future proof transcript admits these claims;
//! it never grants publication without a committed 47-row proof.

const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const views = @import("segment_leaf_wrapper_cohort_views_v3.zig");
const extra = @import("segment_leaf_wrapper_cohort_direct_rows_v4.zig");
const provider = @import("segment_leaf_wrapper_cohort_provider_v3.zig");
const range_provider = @import("segment_leaf_wrapper_range_provider_direct_v4.zig");
const frame_provider = @import("segment_leaf_wrapper_frame_provider_direct_v4.zig");
const relation = @import("../air/lang/relation.zig");
const universal = @import("air/universal_challenges.zig");
const provider_relations = @import("air/universal_provider_relations.zig");
const boundary_mod = @import("segment_public_wire_boundary_v2.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW_COUNT: usize = plan_mod.COMPONENT_COUNT;
pub const DOMAIN_COUNT: usize = universal.RELATION_COUNT;
pub const DomainAudit = extra.DomainAudit;
pub const PublicWireBoundaryV2 = boundary_mod.PublicWireBoundaryV2;

pub const Claims47 = struct {
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
        appended: *const extra.AuditedClaims,
        relations: *const universal.UniversalRelations,
        shared: *const provider_relations.SharedProviderRelations,
    ) !Claims47 {
        try plan.validate();
        try relations.validate();
        try shared.validateAgainst(relations);
        if (reused.present_mask != views.REUSED_MASK or
            try row34_writer.logSize() != plan.placements[34].?.geometry.log_size or
            row34_writer.buffer.calls.len != plan.poseidon_calls.total)
            return error.DirectLeafClaimCoverageMismatch;
        var result = Claims47{
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
        @memcpy(result.claims[39..47], &appended.claims);
        @memcpy(result.audits[39..47], &appended.audits);
        result.present_mask |= ((@as(u64, 1) << extra.ROW_COUNT) - 1) << 39;
        if (result.present_mask != (@as(u64, 1) << ROW_COUNT) - 1)
            return error.DirectLeafClaimCoverageMismatch;
        try result.validateRows();
        return result;
    }

    pub fn validateRows(self: *const Claims47) !void {
        if (self.present_mask != (@as(u64, 1) << ROW_COUNT) - 1)
            return error.DirectLeafClaimCoverageMismatch;
        for (self.claims, self.audits, 0..) |claim, audit, row| {
            try boundary_mod.requireCanonical(claim);
            try boundary_mod.requireCanonical(audit.total);
            const empty = audit.logical_rows == 0 and audit.event_terms == 0;
            if ((audit.logical_rows == 0) != (audit.event_terms == 0) or
                (empty and !claim.isZero()))
                return error.DirectLeafAuditGeometryMismatch;
            var total = QM31.zero();
            for (audit.values, 0..) |value, domain| {
                try boundary_mod.requireCanonical(value);
                if (empty and !value.isZero()) return error.DirectLeafAuditGeometryMismatch;
                if (row == 34 and domain != @intFromEnum(relation.Domain.poseidon2) and
                    domain != @intFromEnum(relation.Domain.poseidon2_io) and !value.isZero())
                    return error.DirectLeafProviderDomainMismatch;
                if (row == 35 and domain != @intFromEnum(relation.Domain.range_check_8_8) and
                    !value.isZero()) return error.DirectLeafProviderDomainMismatch;
                total = total.add(value);
            }
            if (!total.eql(audit.total) or !audit.total.eql(claim))
                return error.DirectLeafClaimMismatch;
            if (row == 10 and !claim.isZero()) return error.DirectLeafClaimMismatch;
        }
    }

    /// Requires a typed V2 local public-wire boundary. Any additional public
    /// global-statement boundary must be added as a separately authenticated
    /// protocol type before proof activation; residuals fail closed today.
    pub fn verifyAllDomains(
        self: *const Claims47,
        plan: *const plan_mod.Plan,
        boundary: *const PublicWireBoundaryV2,
    ) !Summary {
        const summary = try self.residuals(plan, boundary);
        for (summary.domain_totals) |value| if (!value.isZero()) return error.DirectLeafRelationNotClosed;
        if (!summary.framework_total.isZero()) return error.DirectLeafRelationNotClosed;
        return summary;
    }

    /// Cold diagnostic. Nonzero residuals are never accepted as a proof.
    pub fn residuals(
        self: *const Claims47,
        plan: *const plan_mod.Plan,
        boundary: *const PublicWireBoundaryV2,
    ) !Summary {
        try plan.validate();
        try self.validateRows();
        try boundary.validate();
        var totals = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
        var framework_total = boundary.claimed_sum;
        var logical_rows: u64 = 0;
        var event_terms: u64 = 0;
        for (self.claims, self.audits) |claim, audit| {
            framework_total = framework_total.add(claim);
            logical_rows = try std.math.add(u64, logical_rows, audit.logical_rows);
            event_terms = try std.math.add(u64, event_terms, audit.event_terms);
            for (audit.values, 0..) |value, domain| totals[domain] = totals[domain].add(value);
        }
        totals[@intFromEnum(boundary.domain)] = totals[@intFromEnum(boundary.domain)].add(boundary.claimed_sum);
        return .{ .domain_totals = totals, .framework_total = framework_total, .logical_rows = logical_rows, .event_terms = event_terms };
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

test "direct 47-domain closure rejects changed claim and cross-domain substitution" {
    var value = Claims47{
        .claims = @splat(QM31.zero()),
        .audits = @splat(emptyAudit()),
        .present_mask = (@as(u64, 1) << ROW_COUNT) - 1,
    };
    try value.validateRows();
    value.claims[42] = QM31.one();
    try std.testing.expectError(error.DirectLeafAuditGeometryMismatch, value.validateRows());
    value.claims[42] = QM31.zero();
    value.audits[34].values[@intFromEnum(relation.Domain.recursion_wire)] = QM31.one();
    value.audits[34].total = QM31.one();
    value.audits[34].logical_rows = 1;
    value.audits[34].event_terms = 4;
    value.claims[34] = QM31.one();
    try std.testing.expectError(error.DirectLeafProviderDomainMismatch, value.validateRows());
    value.audits[34] = emptyAudit();
    value.claims[34] = QM31.zero();
    value.audits[39].logical_rows = 1;
    try std.testing.expectError(error.DirectLeafAuditGeometryMismatch, value.validateRows());
}

test "direct 47-row claims combine generated provider and audited appended rows" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const program_mod = @import("ethereum_leaf_link_program_v3.zig");
    const calls_mod = @import("segment_leaf_wrapper_cohort_calls_v3.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    const plan = try plan_mod.Plan.build(allocator, &base, &program, .{
        .program_words = 100,
        .base_poseidon_calls = 1193,
    });
    const calls = try allocator.alloc(calls_mod.Call, plan.poseidon_calls.total);
    defer allocator.free(calls);
    for (calls, 0..) |*call, index| call.* = .{
        .input = @splat(@intCast(index + 1)),
        .io = true,
    };
    const parts = [_][]const calls_mod.Call{
        calls[0..1193], calls[1193..1270], calls[1270..1277], calls[1277..1290],
    };
    var buffer = try calls_mod.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    const writer = try provider.Writer.initForDirectPlan(allocator, &plan, &buffer, &parts);
    const relations = universal.UniversalRelations.dummy();
    const shared = try provider_relations.SharedProviderRelations.init(&relations);
    var generated = try writer.generateInteraction(&shared);
    defer generated.deinit(allocator);
    var reused = views.ReusedClaims{
        .claims = @splat(QM31.zero()),
        .audits = @splat(emptyAudit()),
        .present_mask = views.REUSED_MASK,
    };
    var appended = extra.AuditedClaims{
        .claims = @splat(QM31.zero()),
        .audits = @splat(emptyAudit()),
    };
    const row35 = range_provider.ClaimAudit{ .claim = QM31.zero(), .audit = emptyAudit() };
    const row4 = frame_provider.ClaimAudit{ .claim = QM31.zero(), .audit = emptyAudit() };
    const combined = try Claims47.fromGenerated(&plan, &reused, &writer, &generated, &row35, &row4, &appended, &relations, &shared);
    try std.testing.expectEqual((@as(u64, 1) << ROW_COUNT) - 1, combined.present_mask);
    try std.testing.expect(combined.claims[34].eql(generated.claims.total()));
    try std.testing.expectEqual(buffer.calls.len, combined.audits[34].logical_rows);
    var source_id = [_]u8{0} ** 32;
    source_id[0] = 1;
    const boundary = try PublicWireBoundaryV2.init(source_id, 1, QM31.zero());
    try std.testing.expectError(error.DirectLeafRelationNotClosed, combined.verifyAllDomains(&plan, &boundary));
    appended.claims[0] = QM31.one();
    try std.testing.expectError(error.DirectLeafAuditGeometryMismatch, Claims47.fromGenerated(&plan, &reused, &writer, &generated, &row35, &row4, &appended, &relations, &shared));
    appended.claims[0] = QM31.zero();
    reused.present_mask &= ~(@as(u64, 1) << 36);
    try std.testing.expectError(error.DirectLeafClaimCoverageMismatch, Claims47.fromGenerated(&plan, &reused, &writer, &generated, &row35, &row4, &appended, &relations, &shared));
}
