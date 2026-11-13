const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const public_data_mod = @import("stwo_riscv_rv32").air.public_data;
const leaf_owner = @import("segment_leaf_authority.zig");
const claim = @import("stwo_riscv_rv32").recursion.vm_public_claim;
const source = @import("segment_statement_outer_source.zig");
const framework = @import("stwo_riscv_air_lang").framework.framework_interaction;
const manifest_mod = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
const roster = @import("stwo_riscv_air_lang").framework.universal_roster;
const shared_provider = @import("stwo_riscv_rv32").recursion.air.universal_shared_provider;
const universal = @import("stwo_riscv_air_lang").framework.universal_challenges;
const row10_relation = @import("stwo_riscv_recursion_air").statement.input_relation;
const row10_witness = @import("stwo_riscv_rv32").recursion.air.statement_input_witness;
const row11_relation = @import("stwo_riscv_recursion_air").statement.semantics_input_relation;
const row11_witness = @import("stwo_riscv_rv32").recursion.air.statement_semantics_input_witness;
const range_bridge = @import("stwo_riscv_rv32").recursion.air.range_check_8_8_bridge;

const test_support = @import("segment_statement_outer_source_test_support.zig");
const authorityFailureCase = test_support.authorityFailureCase;
const workspaceFailureCase = test_support.workspaceFailureCase;
const preparedFailureCase = test_support.preparedFailureCase;
const OwnedColumns = test_support.OwnedColumns;
const expectCommittedColumns = test_support.expectCommittedColumns;
const expectColumnsEqual = test_support.expectColumnsEqual;
const Fixture = test_support.Fixture;
const TreeKind = test_support.TreeKind;
const Tree = test_support.Tree;
const test_input_words = test_support.test_input_words;
const test_output_words = test_support.test_output_words;
const testPublicData = test_support.testPublicData;

test "R-012 segment statement outer source releases every cold allocation failure" {
    const allocator = std.testing.allocator;
    const data = testPublicData();
    var leaf_preprocessing = try leaf_owner.Preprocessing.init(
        allocator,
        try claim.Shape.init(3, 3),
    );
    defer leaf_preprocessing.deinit();
    var leaf = try leaf_owner.Prepared.init(
        allocator,
        &leaf_preprocessing,
        &data,
    );
    defer leaf.deinit();

    try std.testing.checkAllAllocationFailures(
        allocator,
        authorityFailureCase,
        .{&leaf_preprocessing},
    );
    try std.testing.checkAllAllocationFailures(
        allocator,
        workspaceFailureCase,
        .{},
    );

    var authority = try source.Authority.init(allocator, &leaf_preprocessing);
    defer authority.deinit();
    var workspace = try source.Workspace.init(allocator);
    defer workspace.deinit();
    try std.testing.checkAllAllocationFailures(
        allocator,
        preparedFailureCase,
        .{
            &authority,
            &workspace,
            &leaf_preprocessing,
            &data,
            &leaf,
        },
    );
}

test "R-012 segment statement outer source hot fills allocate zero" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var pp10 = try OwnedColumns(row10_witness.PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer pp10.deinit();
    var pp11 = try OwnedColumns(row11_witness.PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer pp11.deinit();
    var pp35 = try OwnedColumns(range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        source.RANGE_CHECK_TRACE_SIZE,
    );
    defer pp35.deinit();
    var preprocessed = source.PreprocessedColumns{
        .statement_input = pp10.columns,
        .statement_semantics = pp11.columns,
        .range_check = pp35.columns,
    };

    var main10 = try OwnedColumns(row10_witness.MAIN_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer main10.deinit();
    var main11 = try OwnedColumns(row11_witness.MAIN_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer main11.deinit();
    var main35 = try OwnedColumns(range_bridge.PHYSICAL_MAIN_COLUMN_COUNT).init(
        allocator,
        source.RANGE_CHECK_TRACE_SIZE,
    );
    defer main35.deinit();
    var main = source.MainColumns{
        .statement_input = main10.columns,
        .statement_semantics = main11.columns,
        .range_check = main35.columns,
    };

    var interaction10 = try OwnedColumns(row10_relation.Runtime.INTERACTION_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer interaction10.deinit();
    var interaction11 = try OwnedColumns(row11_relation.Runtime.INTERACTION_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer interaction11.deinit();
    var interaction35 = try OwnedColumns(range_bridge.INTERACTION_COLUMN_COUNT).init(
        allocator,
        source.RANGE_CHECK_TRACE_SIZE,
    );
    defer interaction35.deinit();
    var interactions = source.InteractionColumns{
        .statement_input = interaction10.columns,
        .statement_semantics = interaction11.columns,
        .range_check = interaction35.columns,
    };
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );

    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const measured_allocator = measured.allocator();
    const saved_authority_allocator = fixture.authority.allocator;
    const saved_workspace_allocator = fixture.workspace.allocator;
    const saved_prepared_allocator = fixture.prepared.allocator;
    const saved_evaluation_allocator =
        fixture.prepared.circuit_evaluation.allocator;
    const saved_range_allocator =
        fixture.prepared.range.range_check.allocator;
    fixture.authority.allocator = measured_allocator;
    fixture.workspace.allocator = measured_allocator;
    fixture.prepared.allocator = measured_allocator;
    fixture.prepared.circuit_evaluation.allocator = measured_allocator;
    fixture.prepared.range.range_check.allocator = measured_allocator;
    defer {
        fixture.prepared.range.range_check.allocator = saved_range_allocator;
        fixture.prepared.circuit_evaluation.allocator =
            saved_evaluation_allocator;
        fixture.prepared.allocator = saved_prepared_allocator;
        fixture.workspace.allocator = saved_workspace_allocator;
        fixture.authority.allocator = saved_authority_allocator;
    }

    for (0..2) |_| {
        try source.fillPreprocessedCommitted(
            &fixture.authority,
            &fixture.workspace,
            &preprocessed,
        );
        try source.fillMainCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &main,
        );
        const claims = try source.fillInteractionsCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &relations,
            &provider_relations,
            &interactions,
        );
        try claims.verifyRangeClosure();
    }
    try std.testing.expectEqual(@as(usize, 0), measured.alloc_index);
}
