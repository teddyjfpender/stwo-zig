//! Versioned direct-50 closure with typed V6 row36 and verifier-supplied
//! global span boundary. This is a diagnostic claim gate, not a proof gate.

const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const roster = @import("air/segment_leaf_wrapper_roster_direct_v6.zig");
const legacy = @import("segment_leaf_wrapper_cohort_closure_v5.zig");
const row36 = @import("segment_leaf_wrapper_row36_direct_v6.zig");
const global = @import("segment_leaf_wrapper_global_statement_boundary_v6.zig");
const wire = @import("segment_public_wire_boundary_v2.zig");
const las2 = @import("segment_leaf_wrapper_las2_boundary_v4.zig");
const universal = @import("air/universal_challenges.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Summary = legacy.Summary;

pub const ClaimsV6 = struct {
    physical: legacy.Claims50,

    /// The other 49 claims can be reused while their AIR stays identical.
    /// The caller must provide row36 from the V6 physical writer.
    pub fn replaceRow36(plan: *const roster.Plan, other_rows: *const legacy.Claims50, replacement: row36.Claim) !ClaimsV6 {
        try plan.validate();
        var physical = other_rows.*;
        physical.claims[36] = replacement.total;
        physical.audits[36] = replacement.audit;
        try physical.validateRows();
        return .{ .physical = physical };
    }

    pub fn residuals(
        self: *const ClaimsV6,
        plan: *const roster.Plan,
        v2_boundary: *const wire.PublicWireBoundaryV2,
        link_boundary: *const las2.BoundaryV4,
        link_expected: las2.ExpectedPublic,
        global_boundary: *const global.BoundaryV6,
        global_expected: global.ExpectedPublic,
        relations: *const universal.UniversalRelations,
    ) !Summary {
        try plan.validate();
        var result = try self.physical.residuals(&plan.legacy_plan, v2_boundary, link_boundary, link_expected, relations);
        try global_boundary.addToClosure(global_expected, relations, &result.domain_totals, &result.framework_total);
        return result;
    }

    pub fn verifyAllDomains(
        self: *const ClaimsV6,
        plan: *const roster.Plan,
        v2_boundary: *const wire.PublicWireBoundaryV2,
        link_boundary: *const las2.BoundaryV4,
        link_expected: las2.ExpectedPublic,
        global_boundary: *const global.BoundaryV6,
        global_expected: global.ExpectedPublic,
        relations: *const universal.UniversalRelations,
    ) !Summary {
        const summary = try self.residuals(plan, v2_boundary, link_boundary, link_expected, global_boundary, global_expected, relations);
        for (summary.domain_totals) |value| if (!value.isZero()) return error.DirectV6RelationNotClosed;
        if (!summary.framework_total.isZero()) return error.DirectV6RelationNotClosed;
        return summary;
    }
};

test "V6 closure adds only verifier-supplied global Statement boundary" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const v4 = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const program_mod = @import("ethereum_leaf_link_program_v3.zig");
    const child_mod = @import("ethereum_leaf_child_field_program_v1.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    var child = try child_mod.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    const plan = try roster.Plan.build(allocator, &manifest, &program, shape, &child, &child_fixture.components, &child_fixture.infra);
    const empty_audit = @import("air/relation_interaction.zig").DomainAudit{
        .values = @splat(QM31.zero()),
        .total = QM31.zero(),
        .logical_rows = 0,
        .event_terms = 0,
    };
    const previous = legacy.Claims50{
        .claims = @splat(QM31.zero()),
        .audits = @splat(empty_audit),
        .present_mask = (@as(u64, 1) << roster.COMPONENT_COUNT) - 1,
    };
    const claims = try ClaimsV6.replaceRow36(&plan, &previous, .{ .total = QM31.zero(), .audit = empty_audit });
    const relations = universal.UniversalRelations.dummy();
    const wire_boundary = try wire.PublicWireBoundaryV2.init([_]u8{1} ** 32, 1, QM31.zero());
    const link_expected = las2.ExpectedPublic{
        .link = [_]u32{0} ** 8,
        .native_program = [_]u32{0} ** 8,
        .native_tree0 = [_]u32{0} ** 8,
    };
    const link_bound = try las2.BoundaryV4.derive(link_expected, &relations);
    var global_expected = global.ExpectedPublic{ .words = @splat(core.fields.m31.M31.zero()) };
    const global_bound = try global.BoundaryV6.derive(global_expected, &relations);
    const baseline = try claims.physical.residuals(&plan.legacy_plan, &wire_boundary, &link_bound, link_expected, &relations);
    const actual = try claims.residuals(&plan, &wire_boundary, &link_bound, link_expected, &global_bound, global_expected, &relations);
    const domain = @intFromEnum(global.DOMAIN);
    try std.testing.expectEqualDeep(baseline.domain_totals[domain].add(global_bound.claimed_sum), actual.domain_totals[domain]);
    global_expected.words[17] = core.fields.m31.M31.one();
    try std.testing.expectError(error.InvalidGlobalStatementBoundaryV6, claims.residuals(&plan, &wire_boundary, &link_bound, link_expected, &global_bound, global_expected, &relations));
}
