const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const PcsConfig = stwo_core.pcs.PcsConfig;
const public_data_v2 = @import("../air/public_data_v2.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const air_v2 = @import("segment_leaf_outer_air_v2.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const boundary_v2 = @import("segment_leaf_outer_authority_v2.zig");
const range_authority_v2 = @import("segment_range_authority_v2.zig");
const transcript_source_v2 = @import("segment_transcript_outer_source_v2.zig");
const transcript = @import("transcript_program_v2.zig");
const schedule = @import("air/verifier_schedule.zig");
const fixed_profile = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const universal = @import("air/universal_challenges.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const manifest_v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_v2 = @import("air/segment_outer_typed_catalog_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const statement_components_v2 = @import("segment_statement_outer_components_v2.zig");
const subject = @import("segment_statement_outer_source_v2.zig");

const config = PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

const component_descs = [_]statement_v1.FamilyComponentDesc{.{
    .family = .base_alu_imm,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 10,
}};

const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 2,
}};

const test_support = @import("segment_statement_outer_source_v2_test_support.zig");
const Fixture = test_support.Fixture;
const OwnedDestinations = test_support.OwnedDestinations;
const OwnedTree = test_support.OwnedTree;
const sourceTrace = test_support.sourceTrace;
const testPlan = test_support.testPlan;
const qm31 = test_support.qm31;
const counterDigest = test_support.counterDigest;
const providerManifest = test_support.providerManifest;
const statementComponentManifest = test_support.statementComponentManifest;
const expectComponentColumnsZero = test_support.expectComponentColumnsZero;
const providerBoundaryComponents = test_support.providerBoundaryComponents;
const testDigest = test_support.testDigest;
const testShaDigest = test_support.testShaDigest;

test "V2 row-11 statement source has a pinned typed authority" {
    const computed = try air_v2.StatementSemanticsV2.computeSemanticDigest(
        std.testing.allocator,
    );
    try std.testing.expectEqualSlices(
        u8,
        &air_v2.StatementSemanticsV2.SEMANTIC_DIGEST,
        &computed,
    );
    var authority = try subject.AuthorityV2.init(std.testing.allocator);
    defer authority.deinit();
    try authority.validate();
    try std.testing.expectEqual(@as(usize, 0), subject.HOT_PREPARE_HEAP_ALLOCATIONS);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expectEqual(@as(usize, 3), subject.COMPONENT_OVERRIDE_TABLE_V2.len);
    try std.testing.expectEqual(@as(u8, 10), subject.COMPONENT_OVERRIDE_TABLE_V2[0].component_index);
    try std.testing.expectEqual(@as(u8, 11), subject.COMPONENT_OVERRIDE_TABLE_V2[1].component_index);
    try std.testing.expectEqual(@as(u8, 36), subject.COMPONENT_OVERRIDE_TABLE_V2[2].component_index);
    try std.testing.expectEqualSlices(
        u8,
        &air_v2.StatementSemanticsV2.SEMANTIC_DIGEST,
        &subject.COMPONENT_OVERRIDE_TABLE_V2[1].semantic_digest,
    );
}

test "V2 row-11 closes boundary words and exact ProgramV2 statement payloads" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const keys = try source_v2.VerifierKeyAuthorityV2.init(
        support.id("statement-spine-leaf-vk"),
        support.id("statement-spine-parent-vk"),
    );
    const source_shape = try source_v2.preflight(&fixture.data, &keys);
    const source_storage = try std.testing.allocator.alloc(
        M31,
        source_shape.source_trace_column_words,
    );
    defer std.testing.allocator.free(source_storage);
    var source_prepared: source_v2.PreparedV2 = undefined;
    try source_v2.prepareInto(
        &source_prepared,
        sourceTrace(source_storage, source_shape.manifest.trace_row_count),
        &fixture.data,
        &keys,
    );

    const evidence = try fixture.execution.evidence(&fixture.program);
    const transcript_prepared = try transcript_source_v2.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    const manifest = try subject.preflight(
        &fixture.data,
        &source_prepared,
        &transcript_prepared,
        fixture.program.statement_authority_id,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(fixture.words.len + source_v2.CONTEXT_WORD_COUNT + 8)),
        manifest.logical_row_count,
    );

    var owned = try OwnedDestinations.init(std.testing.allocator, manifest);
    defer owned.deinit();
    var authority = try subject.AuthorityV2.init(std.testing.allocator);
    defer authority.deinit();
    var direct_workspace = subject.WorkspaceV2{};
    var prepared: subject.PreparedV2 = undefined;
    try subject.prepareInto(
        &prepared,
        &direct_workspace,
        &authority,
        owned.destinations(),
        &fixture.data,
        &source_prepared,
        &transcript_prepared,
        fixture.program.statement_authority_id,
    );
    try prepared.validate();
    try std.testing.expect(!prepared.row10_active);
    try std.testing.expect(prepared.row10_claim.isZero());
    try prepared.validateRow35RequestSource();
    const closure = try subject.closureLedger(&prepared);
    try closure.validate();
    try std.testing.expectEqual(
        closure.source36_statement_emits,
        closure.row11_statement_consumes,
    );
    try std.testing.expectEqual(
        closure.program_statement_payload_emits,
        closure.row11_statement_payload_consumes,
    );
    try std.testing.expectEqual(
        closure.row11_boundary_wire_emits,
        closure.row15_boundary_wire_consumes,
    );
    try std.testing.expect(closure.source37_row16_namespaces_disjoint);
    try std.testing.expect(closure.source37_custom_producer_closed);
    var stale_closure = closure;
    stale_closure.source37_custom_producer_closed = false;
    try std.testing.expectError(error.SourceMismatch, stale_closure.validate());

    var source_consumes: usize = 0;
    var header_consumes: usize = 0;
    var wire_id_consumes: usize = 0;
    var wire_consumes: usize = 0;
    var boundary_wire_emits: usize = 0;
    for (owned.events) |event| {
        try event.validate();
        if (event.multiplicity == 0) continue;
        if (event.ordinal == 0) source_consumes += 1;
        if (event.ordinal == 1 or event.ordinal == 2) switch (event.tuple[2].toU32()) {
            air_v2.StatementSemanticsV2.HEADER_ITEM => header_consumes += 1,
            air_v2.StatementSemanticsV2.WIRE_ID_ITEM => wire_id_consumes += 1,
            air_v2.StatementSemanticsV2.WIRE_WORD_ITEM => wire_consumes += 1,
            else => return error.TestUnexpectedResult,
        };
        if (event.ordinal == 6) {
            try std.testing.expectEqual(
                air_v2.StatementSemanticsV2.BOUNDARY_BRIDGE_CIRCUIT_ID,
                event.tuple[0].toU32(),
            );
            try std.testing.expect(event.tuple[3].isZero());
            try std.testing.expect(event.tuple[4].isZero());
            try std.testing.expect(event.tuple[5].isZero());
            const index: usize = @intCast(event.tuple[1].toU32());
            try std.testing.expect(index < fixture.words.len);
            try std.testing.expect(event.tuple[2].eql(fixture.words[index]));
            boundary_wire_emits += 1;
        }
    }
    try std.testing.expectEqual(
        fixture.words.len + source_v2.CONTEXT_WORD_COUNT,
        source_consumes,
    );
    try std.testing.expectEqual(@as(usize, 8), header_consumes);
    try std.testing.expectEqual(@as(usize, 16), wire_id_consumes);
    try std.testing.expectEqual(fixture.words.len, wire_consumes);
    try std.testing.expectEqual(fixture.words.len, boundary_wire_emits);
    try std.testing.expectEqual(
        @as(usize, manifest.range_request_count),
        owned.ranges.len,
    );

    const relations = universal.UniversalRelations.dummy();
    var interaction_workspace = try subject.Framework.Workspace.init(
        std.testing.allocator,
        manifest.trace_log_size,
    );
    defer interaction_workspace.deinit();
    const interaction_storage = try std.testing.allocator.alloc(
        M31,
        air_v2.StatementSemanticsV2.INTERACTION_COLUMN_COUNT *
            manifest.trace_row_count,
    );
    defer std.testing.allocator.free(interaction_storage);
    var interaction: [air_v2.StatementSemanticsV2.INTERACTION_COLUMN_COUNT][]M31 =
        undefined;
    for (&interaction, 0..) |*column, index| column.* = interaction_storage[index * manifest.trace_row_count ..][0..manifest.trace_row_count];
    _ = try subject.generateInteractionInto(
        &interaction_workspace,
        &authority,
        &prepared,
        owned.logical_rows,
        &relations,
        &interaction,
    );

    var range_workspace = try range_authority_v2.WorkspaceV2.init(
        std.testing.allocator,
    );
    defer range_workspace.deinit(std.testing.allocator);
    const range_sources = range_authority_v2.SourcesV2{
        .statement = &prepared,
        .logical_rows = owned.logical_rows,
    };
    var partial_range = try range_authority_v2.PreparedPartialV2.init(
        std.testing.allocator,
        &range_workspace,
        range_sources,
    );
    defer partial_range.deinit();
    try partial_range.validateAgainst(
        &range_workspace,
        range_sources,
    );
    try std.testing.expectEqual(
        @as(u64, manifest.range_request_count),
        partial_range.request_count,
    );
    try std.testing.expect(partial_range.productionReady());
    try std.testing.expect((try partial_range.publication()) ==
        partial_range.provider());

    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );
    var provider_interaction = try partial_range.generateProviderInteraction(
        std.testing.allocator,
        &provider_relations,
    );
    defer provider_interaction.deinit();
    try provider_interaction.validate();
    try partial_range.verifyExactClosure(
        range_sources,
        &relations,
        provider_interaction.claim(),
    );
    var bad_provider_claim = provider_interaction.claim();
    bad_provider_claim = bad_provider_claim.add(QM31.one());
    try std.testing.expectError(
        error.RequestProviderClosureMismatch,
        partial_range.verifyExactClosure(
            range_sources,
            &relations,
            bad_provider_claim,
        ),
    );

    var provider_authority = try range_authority_v2.ProviderAuthorityV2.init(
        std.testing.allocator,
    );
    defer provider_authority.deinit();
    const v2_manifest = try providerManifest(manifest.trace_log_size);
    var provider_component = try provider_interaction.component(
        &provider_authority,
        &v2_manifest,
        &provider_relations,
        &relations,
    );
    const provider_binding = try provider_component.binding(&v2_manifest);
    try std.testing.expect(provider_binding.claimed_sum.eql(
        provider_interaction.claim(),
    ));

    // Rows 10 and 11 now cross the complete concrete component boundary:
    // typed adapters, all three commitment trees, claims, and exact-domain
    // audits all consume the same authenticated logical-row custody.
    const statement_manifest = try statementComponentManifest(&prepared);
    var component_authority = try statement_components_v2.AuthorityV2.init(
        std.testing.allocator,
    );
    defer component_authority.deinit();
    var component_workspace = try statement_components_v2.WorkspaceV2.init(
        std.testing.allocator,
        &prepared,
    );
    defer component_workspace.deinit();
    var tree0 = try OwnedTree.init(
        std.testing.allocator,
        &statement_manifest,
        manifest_v2.PREPROCESSED_TREE_INDEX,
    );
    defer tree0.deinit();
    var tree1 = try OwnedTree.init(
        std.testing.allocator,
        &statement_manifest,
        manifest_v2.MAIN_TREE_INDEX,
    );
    defer tree1.deinit();
    var tree2 = try OwnedTree.init(
        std.testing.allocator,
        &statement_manifest,
        manifest_v2.INTERACTION_TREE_INDEX,
    );
    defer tree2.deinit();
    tree0.fillSentinel();
    tree1.fillSentinel();
    tree2.fillSentinel();
    try statement_components_v2.fillPreprocessedInto(
        &component_authority,
        &prepared,
        owned.logical_rows,
        &statement_manifest,
        tree0.columns,
    );
    try statement_components_v2.fillMainInto(
        &component_authority,
        &prepared,
        owned.logical_rows,
        &statement_manifest,
        tree1.columns,
    );
    const statement_claims = try statement_components_v2.fillInteractionInto(
        &component_authority,
        &component_workspace,
        &prepared,
        owned.logical_rows,
        &statement_manifest,
        &relations,
        tree2.columns,
    );
    try statement_claims.validate();
    try std.testing.expect(statement_claims.row10_inactive.isZero());
    try expectComponentColumnsZero(
        &statement_manifest,
        .statement_input,
        manifest_v2.PREPROCESSED_TREE_INDEX,
        tree0.columns,
    );
    try expectComponentColumnsZero(
        &statement_manifest,
        .statement_input,
        manifest_v2.MAIN_TREE_INDEX,
        tree1.columns,
    );
    try expectComponentColumnsZero(
        &statement_manifest,
        .statement_input,
        manifest_v2.INTERACTION_TREE_INDEX,
        tree2.columns,
    );
    const row11_placement = try statement_manifest.placement(
        .statement_semantics_input,
    );
    const first_committed = @import("air/framework_interaction.zig").committedRow(
        0,
        row11_placement.geometry.log_size,
    );
    try std.testing.expect(tree1.columns[
        row11_placement.main_offset
    ][first_committed].eql(owned.logical_rows[0][0]));
    try std.testing.expect(tree0.columns[
        row11_placement.preprocessed_offset
    ][first_committed].eql(owned.logical_rows[0][subject.Air.PHYSICAL_MAIN_COLUMN_COUNT]));

    var claim_vector = try manifest_v2.ClaimVector.init(&statement_manifest);
    try statement_claims.bindInto(&claim_vector);
    var components = try component_authority.initComponents(
        &prepared,
        &statement_manifest,
        &relations,
        statement_claims,
    );
    const row10_binding = try components.row10_inactive.binding(
        &statement_manifest,
    );
    const row11_binding = try components.row11_statement.binding(
        &statement_manifest,
    );
    try std.testing.expect(row10_binding.claimed_sum.isZero());
    try std.testing.expect(row11_binding.claimed_sum.eql(
        statement_claims.row11_statement,
    ));
    const audits = try statement_components_v2.auditInteractionDomains(
        std.testing.allocator,
        &component_authority,
        &prepared,
        owned.logical_rows,
        &statement_manifest,
        &relations,
        statement_claims,
        null,
    );
    try std.testing.expect(audits.row10_inactive.total.isZero());
    try std.testing.expect(audits.row11_statement.total.eql(
        statement_claims.row11_statement,
    ));

    // Authenticated-row mutation is rejected before the first externally
    // committed Tree-2 cell changes.
    tree2.fillSentinel();
    const tree2_before = tree2.digest();
    owned.logical_rows[0][0] = owned.logical_rows[0][0].add(M31.one());
    try std.testing.expectError(
        error.TraceMutation,
        statement_components_v2.fillInteractionInto(
            &component_authority,
            &component_workspace,
            &prepared,
            owned.logical_rows,
            &statement_manifest,
            &relations,
            tree2.columns,
        ),
    );
    try std.testing.expectEqual(tree2_before, tree2.digest());
    owned.logical_rows[0][0] = owned.logical_rows[0][0].sub(M31.one());

    var rejected = try OwnedDestinations.init(std.testing.allocator, manifest);
    defer rejected.deinit();
    rejected.fillSentinel();
    const rejected_before = rejected.digest();
    var bad_transcript = transcript_prepared;
    bad_transcript.authority.wire_id[0] ^= 1;
    var rejected_prepared: subject.PreparedV2 = undefined;
    try std.testing.expectError(
        error.SourceMismatch,
        subject.prepareInto(
            &rejected_prepared,
            &direct_workspace,
            &authority,
            rejected.destinations(),
            &fixture.data,
            &source_prepared,
            &bad_transcript,
            fixture.program.statement_authority_id,
        ),
    );
    try std.testing.expectEqual(rejected_before, rejected.digest());

    const counter_before = counterDigest(range_workspace.counter.values);
    owned.logical_rows[0][0] = owned.logical_rows[0][0].add(M31.one());
    try std.testing.expectError(
        error.TraceMutation,
        partial_range.validateAgainst(&range_workspace, range_sources),
    );
    try std.testing.expectEqual(counter_before, counterDigest(range_workspace.counter.values));
    owned.logical_rows[0][0] = owned.logical_rows[0][0].sub(M31.one());
}
