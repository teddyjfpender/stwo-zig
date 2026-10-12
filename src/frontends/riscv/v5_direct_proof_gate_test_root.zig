const std = @import("std");
const core = @import("stwo_core");
const roster = @import("recursion/air/segment_leaf_wrapper_roster_direct_v5.zig");
const gate = @import("recursion/air/segment_leaf_wrapper_proof_gate_direct_v5.zig");
const closure = @import("recursion/segment_leaf_wrapper_cohort_closure_v5.zig");
const catalog = @import("recursion/air/segment_outer_typed_catalog_v2.zig");
const v2 = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const v4 = @import("recursion/air/segment_leaf_wrapper_roster_direct_v4.zig");
const link_program = @import("recursion/ethereum_leaf_link_program_v3.zig");
const child_program = @import("recursion/ethereum_leaf_child_field_program_v1.zig");
const child_fixture = @import("recursion/tests/ethereum_leaf_child_field_test.zig");
const fixture = @import("wrapper_roster_v3_test_root.zig");
const QM31 = core.fields.qm31.QM31;

test "V5 gate binds exact 50 rows and remains proof-inactive" {
    std.testing.refAllDecls(gate);
    try std.testing.expect(@hasDecl(roster, "AdapterBinding"));
    try std.testing.expectEqual(@as(usize, 50), gate.COMPONENT_COUNT);
    try std.testing.expect(!gate.COMPLETE_PROOF_AVAILABLE);
    try std.testing.expectEqual(gate.AdapterOwner.native_v2, try gate.ownerForRow(0));
    try std.testing.expectEqual(gate.AdapterOwner.frame_provider_v4, try gate.ownerForRow(4));
    try std.testing.expectEqual(gate.AdapterOwner.poseidon_provider_v5, try gate.ownerForRow(34));
    try std.testing.expectEqual(gate.AdapterOwner.statement_v5, try gate.ownerForRow(36));
    try std.testing.expectEqual(gate.AdapterOwner.direct_v4, try gate.ownerForRow(41));
    try std.testing.expectEqual(gate.AdapterOwner.program_bridge_v5, try gate.ownerForRow(42));
    try std.testing.expectEqual(gate.AdapterOwner.local_v5, try gate.ownerForRow(49));
    try std.testing.expectError(error.InvalidV5ProofGateRow, gate.ownerForRow(50));
    const allocator = std.testing.allocator;
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base_manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var link = try link_program.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try child_program.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    const plan = try roster.Plan.build(allocator, &base_manifest, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    var audit = try gate.BindingAudit.init(&plan);
    const first = plan.placements[0].?;
    const first_constraints = @as(usize, first.geometry.direct_constraints) + first.geometry.interaction_batches;
    try std.testing.expectError(error.InvalidV5ProofGatePlacement, audit.bind(&plan, plan.placements[1].?, QM31.zero(), first_constraints, first_constraints));
    try std.testing.expectError(error.InvalidV5ProofGateComponent, audit.bind(&plan, first, QM31.zero(), first_constraints + 1, first_constraints));
    try std.testing.expectEqual(@as(u8, 0), audit.count);

    var claims = closure.Claims50{
        .claims = @splat(QM31.zero()),
        .audits = @splat(.{ .values = @splat(QM31.zero()), .total = QM31.zero(), .logical_rows = 0, .event_terms = 0 }),
        .present_mask = gate.ALL_COMPONENT_MASK,
    };
    try std.testing.expectError(error.IncompleteV5ProofGate, audit.sealStructural(&plan, &claims));
    for (plan.placements) |maybe_placement| {
        const placement = maybe_placement.?;
        const n = @as(usize, placement.geometry.direct_constraints) + placement.geometry.interaction_batches;
        try audit.bind(&plan, placement, QM31.zero(), n, n);
    }
    try std.testing.expectEqual(gate.ALL_COMPONENT_MASK, audit.bound_mask);
    try std.testing.expectEqual(@as(u8, 50), audit.count);
    claims.present_mask &= ~(@as(u64, 1) << 49);
    try std.testing.expectError(error.DirectV5ClaimCoverageMismatch, audit.sealStructural(&plan, &claims));
    claims.present_mask = gate.ALL_COMPONENT_MASK;
    try audit.sealStructural(&plan, &claims);
    try audit.validateStructural(&plan);
    audit.claimed_sums[1] = QM31.one();
    try std.testing.expectError(error.IncompleteV5ProofGate, audit.validateStructural(&plan));

    const proof_gate = try gate.ProofGate.init(&plan);
    try std.testing.expectError(error.V5WrapperProofUnavailable, proof_gate.verifierSlice());
    try std.testing.expectError(error.V5WrapperProofUnavailable, proof_gate.proverSlice());
}
