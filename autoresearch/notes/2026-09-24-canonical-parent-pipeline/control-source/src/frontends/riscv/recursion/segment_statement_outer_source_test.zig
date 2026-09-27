const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const public_data_mod = @import("../air/public_data.zig");
const leaf_owner = @import("segment_leaf_authority.zig");
const claim = @import("vm_public_claim.zig");
const source = @import("segment_statement_outer_source.zig");
const framework = @import("air/framework_interaction.zig");
const manifest_mod = @import("air/universal_adapter_manifest.zig");
const roster = @import("air/universal_roster.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const universal = @import("air/universal_challenges.zig");
const row10_relation = @import("air/statement_input_relation.zig");
const row10_witness = @import("air/statement_input_witness.zig");
const row11_relation = @import("air/statement_semantics_input_relation.zig");
const row11_witness = @import("air/statement_semantics_input_witness.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");

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

test "R-012 segment statement outer source graph receipt" {
    const digest = try source.computeLoweringGraphDigest(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &source.LOWERING_GRAPH_DIGEST, &digest);
}

test "R-012 segment statement outer source admits one real leaf" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.prepared.validateAgainst(
        &fixture.authority,
        &fixture.workspace,
        &fixture.leaf_preprocessing,
        &fixture.data,
        &fixture.leaf,
    );
    try fixture.authority.validate();
    try std.testing.expectEqual(
        @as(usize, 73_728),
        source.TOTAL_INTERACTION_TERMS,
    );
    try std.testing.expectEqual(
        source.STATEMENT_CIRCUIT_ID,
        fixture.authority.loweringLane().circuit_id,
    );
    try std.testing.expectEqual(
        fixture.authority.lowering_graph.nodes.len,
        fixture.prepared.loweringEvaluation().values.len,
    );
}

test "R-012 segment statement outer source is exact in all three committed trees" {
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
    try source.fillPreprocessedCommitted(
        &fixture.authority,
        &fixture.workspace,
        &preprocessed,
    );

    var logical_pp10 = try OwnedColumns(row10_witness.PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer logical_pp10.deinit();
    try fixture.authority.statement_input_executor.generatePreprocessedInto(
        &fixture.authority.statement_input_preprocessing,
        &logical_pp10.columns,
    );
    try expectCommittedColumns(
        row10_witness.PREPROCESSED_COLUMN_COUNT,
        source.STATEMENT_INPUT_LOG_SIZE,
        &logical_pp10.columns,
        &pp10.columns,
    );

    var logical_pp11 = try OwnedColumns(row11_witness.PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer logical_pp11.deinit();
    try fixture.authority.statement_semantics_executor.generatePreprocessedInto(
        &fixture.authority.statement_semantics_preprocessing,
        &logical_pp11.columns,
    );
    try expectCommittedColumns(
        row11_witness.PREPROCESSED_COLUMN_COUNT,
        source.STATEMENT_SEMANTICS_LOG_SIZE,
        &logical_pp11.columns,
        &pp11.columns,
    );
    for (0..source.RANGE_CHECK_TRACE_SIZE) |logical_row| {
        const committed = source.committedRow(
            logical_row,
            source.RANGE_CHECK_LOG_SIZE,
        );
        try std.testing.expectEqual(
            M31.fromU64(@intFromBool(logical_row == 0)),
            pp35.columns[0][committed],
        );
        try std.testing.expectEqual(
            M31.fromCanonical(@intCast(logical_row & 0xff)),
            pp35.columns[1][committed],
        );
        try std.testing.expectEqual(
            M31.fromCanonical(@intCast(logical_row >> 8)),
            pp35.columns[2][committed],
        );
    }

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
    try source.fillMainCommitted(
        &fixture.authority,
        &fixture.workspace,
        &fixture.prepared,
        &fixture.leaf_preprocessing,
        &fixture.data,
        &fixture.leaf,
        &main,
    );

    var logical_main10 = try OwnedColumns(row10_witness.MAIN_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer logical_main10.deinit();
    try fixture.authority.statement_input_executor.generateMainInto(
        &fixture.authority.statement_input_preprocessing,
        &logical_main10.columns,
        .{ .segment_leaf = &fixture.prepared.statement_words },
    );
    try expectCommittedColumns(
        row10_witness.MAIN_COLUMN_COUNT,
        source.STATEMENT_INPUT_LOG_SIZE,
        &logical_main10.columns,
        &main10.columns,
    );

    var logical_main11 = try OwnedColumns(row11_witness.MAIN_COLUMN_COUNT).init(
        allocator,
        source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer logical_main11.deinit();
    try fixture.authority.statement_semantics_executor.generateMainInto(
        &fixture.authority.statement_semantics_preprocessing,
        &logical_main11.columns,
        fixture.prepared.statement_values,
        .segment_leaf,
    );
    try expectCommittedColumns(
        row11_witness.MAIN_COLUMN_COUNT,
        source.STATEMENT_SEMANTICS_LOG_SIZE,
        &logical_main11.columns,
        &main11.columns,
    );
    for (fixture.prepared.range.provider().counter.values, 0..) |
        expected,
        logical_row,
    | {
        try std.testing.expectEqual(
            expected,
            main35.columns[0][
                source.committedRow(
                    logical_row,
                    source.RANGE_CHECK_LOG_SIZE,
                )
            ],
        );
    }

    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );
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
    const domain_audits = try source.auditInteractionDomains(
        &fixture.authority,
        &fixture.workspace,
        &fixture.prepared,
        &fixture.leaf_preprocessing,
        &fixture.data,
        &fixture.leaf,
        &relations,
        &provider_relations,
        claims,
        null,
    );
    try std.testing.expect(domain_audits.statement_input.total.eql(
        claims.statement_input,
    ));
    try std.testing.expect(domain_audits.statement_semantics.total.eql(
        claims.statement_semantics,
    ));
    try std.testing.expect(domain_audits.range_check.total.eql(
        claims.range_check,
    ));

    const rows10 = try allocator.alloc(
        row10_relation.Row,
        fixture.authority.statement_input_preprocessing.rows.len,
    );
    defer allocator.free(rows10);
    for (
        rows10,
        fixture.authority.statement_input_preprocessing.rows,
    ) |*row, metadata| row.* = try row10_witness.logicalRow(
        metadata,
        .{ .segment_leaf = &fixture.prepared.statement_words },
    );
    const Row10Framework = framework.Runtime(row10_relation.Runtime);
    var expected10 = try Row10Framework.generatePrepared(
        allocator,
        &fixture.authority.statement_input_relation,
        rows10,
        source.STATEMENT_INPUT_LOG_SIZE,
        &relations,
    );
    defer expected10.deinit(allocator);

    const rows11 = try allocator.alloc(
        row11_relation.Row,
        fixture.authority.statement_semantics_preprocessing.rows.len,
    );
    defer allocator.free(rows11);
    for (
        rows11,
        fixture.authority.statement_semantics_preprocessing.rows,
        fixture.prepared.statement_values,
    ) |*row, metadata, value| row.* = try row11_witness.logicalRow(
        metadata,
        value,
        .segment_leaf,
    );
    const Row11Framework = framework.Runtime(row11_relation.Runtime);
    var expected11 = try Row11Framework.generatePrepared(
        allocator,
        &fixture.authority.statement_semantics_relation,
        rows11,
        source.STATEMENT_SEMANTICS_LOG_SIZE,
        &relations,
    );
    defer expected11.deinit(allocator);
    var expected35 = try fixture.prepared.range.provider().generateNativeInteraction(
        allocator,
        &provider_relations.native,
    );
    defer expected35.deinit(allocator);

    try expectColumnsEqual(
        row10_relation.Runtime.INTERACTION_COLUMN_COUNT,
        &expected10.columns,
        &interaction10.columns,
    );
    try expectColumnsEqual(
        row11_relation.Runtime.INTERACTION_COLUMN_COUNT,
        &expected11.columns,
        &interaction11.columns,
    );
    try expectColumnsEqual(
        range_bridge.INTERACTION_COLUMN_COUNT,
        &expected35.columns,
        &interaction35.columns,
    );
    try std.testing.expect(claims.statement_input.eql(expected10.claimed_sum));
    try std.testing.expect(claims.statement_semantics.eql(expected11.claimed_sum));
    try std.testing.expect(claims.range_check.eql(expected35.claim));

    var expected_requests = QM31.zero();
    for (fixture.prepared.range.provider().counter.values, 0..) |
        multiplicity,
        logical_row,
    | {
        const tuple = [2]M31{
            M31.fromCanonical(@intCast(logical_row & 0xff)),
            M31.fromCanonical(@intCast(logical_row >> 8)),
        };
        const denominator = provider_relations.native.range_check_8_8.combineBase(
            tuple,
        );
        expected_requests = expected_requests.add(
            QM31.fromBase(multiplicity).mul(try denominator.inv()),
        );
    }
    try std.testing.expect(claims.range_requests.eql(expected_requests));
    try claims.verifyRangeClosure();
    const roster_claims = claims.rosterValues();
    try std.testing.expect(roster_claims[0].eql(claims.statement_input));
    try std.testing.expect(roster_claims[1].eql(claims.statement_semantics));
    try std.testing.expect(roster_claims[2].eql(claims.range_check));
}

test "R-012 segment statement outer source binds the global roster without copies" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();

    try std.testing.expectEqualSlices(
        roster.Component,
        &.{
            .statement_input,
            .statement_semantics_input,
            .range_check_8_8,
        },
        &source.ROSTER_ROWS,
    );
    var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
    fixture.authority.installLogSizes(&logs);
    try std.testing.expectEqual(
        source.STATEMENT_INPUT_LOG_SIZE,
        logs[@intFromEnum(roster.Component.statement_input)],
    );
    try std.testing.expectEqual(
        source.STATEMENT_SEMANTICS_LOG_SIZE,
        logs[@intFromEnum(roster.Component.statement_semantics_input)],
    );
    try std.testing.expectEqual(
        source.RANGE_CHECK_LOG_SIZE,
        logs[@intFromEnum(roster.Component.range_check_8_8)],
    );

    var preprocessed_tree = try Tree.init(allocator, &manifest, .preprocessed);
    defer preprocessed_tree.deinit();
    var main_tree = try Tree.init(allocator, &manifest, .main);
    defer main_tree.deinit();
    var interaction_tree = try Tree.init(allocator, &manifest, .interaction);
    defer interaction_tree.deinit();
    var preprocessed = try source.bindPreprocessedCommitted(
        &fixture.authority,
        &manifest,
        preprocessed_tree.columns,
    );
    var main = try source.bindMainCommitted(
        &fixture.authority,
        &manifest,
        main_tree.columns,
    );
    var interactions = try source.bindInteractionsCommitted(
        &fixture.authority,
        &manifest,
        interaction_tree.columns,
    );
    const row10 = try manifest.placement(.statement_input);
    const row11 = try manifest.placement(.statement_semantics_input);
    const row35 = try manifest.placement(.range_check_8_8);
    try std.testing.expectEqual(
        @intFromPtr(preprocessed_tree.columns[row10.preprocessed_offset].ptr),
        @intFromPtr(preprocessed.statement_input[0].ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(main_tree.columns[row11.main_offset].ptr),
        @intFromPtr(main.statement_semantics[0].ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(interaction_tree.columns[row35.interaction_offset].ptr),
        @intFromPtr(interactions.range_check[0].ptr),
    );

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
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
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
    const components = try fixture.authority.components(
        &manifest,
        &relations,
        &provider_relations,
        claims.rosterClaims(),
    );
    try std.testing.expectEqual(row10, components.statement_input.placement);
    try std.testing.expectEqual(row11, components.statement_semantics.placement);
    try std.testing.expectEqual(row35, components.range_check.placement);

    var claim_vector = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bindInto(&claim_vector);
    try claim_vector.sealClaims(&manifest);
    try claim_vector.validate(&manifest);
    const verifier_claims = try source.RosterClaims.fromVector(
        &claim_vector,
        &manifest,
    );
    try std.testing.expectEqualDeep(claims.rosterClaims(), verifier_claims);
    try std.testing.expect(
        claim_vector.values[@intFromEnum(roster.Component.statement_input)].eql(
            claims.statement_input,
        ),
    );
    try std.testing.expect(
        claim_vector.values[@intFromEnum(roster.Component.statement_semantics_input)].eql(
            claims.statement_semantics,
        ),
    );
    try std.testing.expect(
        claim_vector.values[@intFromEnum(roster.Component.range_check_8_8)].eql(
            claims.range_check,
        ),
    );
}

test "R-012 segment statement outer source rejects mutations before commit" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const sentinel = M31.fromCanonical(0x5151);

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
    pp10.fill(sentinel);
    pp11.fill(sentinel);
    pp35.fill(sentinel);
    var preprocessed = source.PreprocessedColumns{
        .statement_input = pp10.columns,
        .statement_semantics = pp11.columns,
        .range_check = pp35.columns,
    };
    preprocessed.statement_input[1] = preprocessed.statement_input[0];
    try std.testing.expectError(
        error.AliasedDestination,
        source.fillPreprocessedCommitted(
            &fixture.authority,
            &fixture.workspace,
            &preprocessed,
        ),
    );
    try pp10.expectFilled(sentinel);
    try pp11.expectFilled(sentinel);
    try pp35.expectFilled(sentinel);

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
    main10.fill(sentinel);
    main11.fill(sentinel);
    main35.fill(sentinel);
    var main = source.MainColumns{
        .statement_input = main10.columns,
        .statement_semantics = main11.columns,
        .range_check = main35.columns,
    };
    const original_main = main.statement_semantics[0];
    main.statement_semantics[0] = original_main[0 .. original_main.len - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        source.fillMainCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &main,
        ),
    );
    main.statement_semantics[0] = original_main;
    try main10.expectFilled(sentinel);
    try main11.expectFilled(sentinel);
    try main35.expectFilled(sentinel);

    const saved_value = fixture.prepared.statement_values[0];
    fixture.prepared.statement_values[0] = saved_value.add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        source.fillMainCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &main,
        ),
    );
    fixture.prepared.statement_values[0] = saved_value;
    try main10.expectFilled(sentinel);
    try main11.expectFilled(sentinel);
    try main35.expectFilled(sentinel);

    const evaluation_index = fixture.prepared.circuit_evaluation.input_count + 7;
    const saved_evaluation =
        fixture.prepared.circuit_evaluation.storage[evaluation_index];
    fixture.prepared.circuit_evaluation.storage[evaluation_index] =
        saved_evaluation.add(QM31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        source.fillMainCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &main,
        ),
    );
    fixture.prepared.circuit_evaluation.storage[evaluation_index] =
        saved_evaluation;
    try main10.expectFilled(sentinel);
    try main11.expectFilled(sentinel);
    try main35.expectFilled(sentinel);

    const saved_multiplicity =
        fixture.prepared.range.provider().counter.values[0];
    fixture.prepared.range.range_check.counter.values[0] =
        saved_multiplicity.sub(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        source.fillMainCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &main,
        ),
    );
    fixture.prepared.range.range_check.counter.values[0] = saved_multiplicity;
    try main10.expectFilled(sentinel);
    try main11.expectFilled(sentinel);
    try main35.expectFilled(sentinel);

    const original_range_main = main.range_check[0];
    main.range_check[0] = fixture.prepared.range.provider().counter.values;
    try std.testing.expectError(
        error.AliasedInput,
        source.fillMainCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &main,
        ),
    );
    main.range_check[0] = original_range_main;
    try fixture.prepared.validateAgainst(
        &fixture.authority,
        &fixture.workspace,
        &fixture.leaf_preprocessing,
        &fixture.data,
        &fixture.leaf,
    );
    try main10.expectFilled(sentinel);
    try main11.expectFilled(sentinel);
    try main35.expectFilled(sentinel);

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
    interaction10.fill(sentinel);
    interaction11.fill(sentinel);
    interaction35.fill(sentinel);
    var interactions = source.InteractionColumns{
        .statement_input = interaction10.columns,
        .statement_semantics = interaction11.columns,
        .range_check = interaction35.columns,
    };
    var bad_relations = universal.UniversalRelations.dummy();
    bad_relations.elements[
        @intFromEnum(
            @import("../air/lang/relation.zig").Domain.range_check_8_8,
        )
    ] = universal.Elements.init(2, QM31.zero(), QM31.zero());
    const bad_provider_relations = try shared_provider.SharedProviderRelations.init(
        &bad_relations,
    );
    try std.testing.expectError(
        error.ZeroDenominator,
        source.fillInteractionsCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &bad_relations,
            &bad_provider_relations,
            &interactions,
        ),
    );
    try interaction10.expectFilled(sentinel);
    try interaction11.expectFilled(sentinel);
    try interaction35.expectFilled(sentinel);

    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );
    const original_range_column = interactions.range_check[0];
    interactions.range_check[0] = fixture.prepared.range.provider().counter.values;
    try std.testing.expectError(
        error.AliasedInput,
        source.fillInteractionsCommitted(
            &fixture.authority,
            &fixture.workspace,
            &fixture.prepared,
            &fixture.leaf_preprocessing,
            &fixture.data,
            &fixture.leaf,
            &relations,
            &provider_relations,
            &interactions,
        ),
    );
    interactions.range_check[0] = original_range_column;
    try fixture.prepared.validateAgainst(
        &fixture.authority,
        &fixture.workspace,
        &fixture.leaf_preprocessing,
        &fixture.data,
        &fixture.leaf,
    );
    try interaction10.expectFilled(sentinel);
    try interaction11.expectFilled(sentinel);
    try interaction35.expectFilled(sentinel);
}

test {
    _ = @import("segment_statement_outer_source_test_continuation_1.zig");
}
