const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const components =
    @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const cohort =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4.zig");
const geometry =
    @import("recursive_common_ethereum_incremental_leaf_transcript_geometry_v4.zig");
const rows =
    @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

test "stage102 role0 transcript cohort tree and tuple APIs instantiate" {
    const Prepared = cohort.PreparedV4(Engine);
    std.testing.refAllDecls(Prepared);
    try std.testing.expect(@hasDecl(Prepared, "fillPreprocessedInto"));
    try std.testing.expect(@hasDecl(Prepared, "fillMainInto"));
    try std.testing.expect(@hasDecl(Prepared, "fillInteractionInto"));
    try std.testing.expect(@hasDecl(Prepared, "appendTupleContributions"));
    try std.testing.expect(cohort.TREE0_AVAILABLE);
    try std.testing.expect(cohort.TREE1_AVAILABLE);
    try std.testing.expect(cohort.TREE2_AVAILABLE);
    try std.testing.expect(cohort.TUPLE_LEDGER_AVAILABLE);
    try std.testing.expect(!cohort.COMPLETE_36_CLAIM_CLOSURE_AVAILABLE);
}

test "stage102 role0 transcript rows retain inactive recursion lanes" {
    std.testing.refAllDecls(rows.OwnerV4(Engine));
    try std.testing.expect(geometry.ROW_MATERIALIZERS_AVAILABLE);
    try std.testing.expect(components.TREE_PUBLICATION_AVAILABLE);
    try std.testing.expect(!components.SEGMENT_V2_NOMINAL_INPUT_ADMITTED);
    try std.testing.expect(!cohort.PRODUCTION_ACTIVATION);
}

test "Ethereum prepared transcript and suffix owners hide mutable rows and plans" {
    const Prefix = cohort.PreparedV4(Engine);
    const Suffix = @import("recursive_common_ethereum_incremental_leaf_suffix_cohort_v4.zig").PreparedV4(Engine);
    try std.testing.expect(@typeInfo(Prefix) == .@"opaque");
    try std.testing.expect(@typeInfo(Suffix) == .@"opaque");
    inline for (.{ Prefix, Suffix }) |Owner| {
        try std.testing.expect(@hasDecl(Owner, "validate"));
        try std.testing.expect(@hasDecl(Owner, "identity"));
        try std.testing.expect(@hasDecl(Owner, "fillInteractionWithAudit"));
        try std.testing.expect(@hasDecl(Owner, "auditClaims"));
        try std.testing.expect(!@hasDecl(Owner, "rows"));
        try std.testing.expect(!@hasDecl(Owner, "components"));
    }
}

test "Ethereum generated interaction audit matches canonical columns and independent cold sums" {
    const allocator = std.testing.allocator;
    const air = frontend.recursion.air;
    const support = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
    var definition = try air.control.build(allocator);
    defer definition.deinit();
    const plan = try components.ControlRelation.authenticate(&definition);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const logical = [_]components.ControlRelation.Row{
        air.control_witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 0, .tag = 7, .args = .{ 11, 13, 17, 19 }, .terminal_mask = 0 }, .segment_leaf),
        air.control_witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 1, .tag = 23, .args = .{ 29, 31, 37, 41 }, .terminal_mask = 1 }, .segment_leaf),
    };
    const before = logical;
    var expected = try components.ControlFramework.generatePrepared(allocator, &plan, &logical, 4, &relations);
    defer expected.deinit(allocator);
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    {
        var actual = try support.generateWithAudit(components.ControlFramework, measured.allocator(), &plan, &logical, 4, &relations);
        defer actual.deinit(measured.allocator());
        // The audit uses the existing inverse plane: only the same output
        // storage and scratch allocations as ordinary generation are needed.
        try std.testing.expectEqual(@as(usize, 2), measured.alloc_index);
        try std.testing.expectEqualDeep(expected.columns, actual.interaction.columns);
        try std.testing.expectEqualDeep(expected.claimed_sum, actual.interaction.claimed_sum);
        try std.testing.expect(!actual.audit.total.isZero());
        const cold = try plan.auditPreparedDomainSums(allocator, &logical, &relations, expected.claimed_sum);
        try std.testing.expectEqualDeep(cold, actual.audit);
        try std.testing.expectEqualDeep(before, logical);
        try std.testing.expectError(error.ClaimMismatch, plan.auditPreparedDomainSums(allocator, &logical, &relations, actual.audit.total.add(@import("stwo_core").fields.qm31.QM31.one())));
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(allocator, auditedInteractionFailureCase, .{ &plan, &logical, &relations });
}

fn auditedInteractionFailureCase(
    allocator: std.mem.Allocator,
    plan: *const components.ControlRelation.Plan,
    logical: []const components.ControlRelation.Row,
    relations: *const frontend.recursion.air.universal_challenges.UniversalRelations,
) !void {
    var generated = try @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig").generateWithAudit(components.ControlFramework, allocator, plan, logical, 4, relations);
    defer generated.deinit(allocator);
}
