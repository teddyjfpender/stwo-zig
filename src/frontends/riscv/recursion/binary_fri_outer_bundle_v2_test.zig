//! Independent acceptance tests for the binary-pair V2 rows-18--34 owner.
//!
//! This file intentionally does not share implementation helpers with
//! `binary_fri_outer_bundle.zig`.  It checks the public manifest and schedule
//! contracts from their respective authorities, then exercises the concrete
//! bundle through a separately owned test root. The honest pair fixture is
//! not the native SegmentV2 leaf: it produces 16,852 verifier calls, while the
//! separately owned native schedule profile records 294.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const bundle_mod = @import("binary_fri_outer_bundle.zig");
const fixture_mod = @import("binary_pair_test_fixture.zig");
const source_mod = @import("binary_fri_outer_source.zig");
const source_test_support = @import("binary_fri_outer_source_test.zig");
const schedule_mod = @import("segment_shared_poseidon_schedule_v2.zig");
const cohort_mod = @import("segment_outer_cohort_v2.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const row17_witness_v2 =
    @import("air/vm_public_logup_control_witness_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const universal = @import("air/universal_challenges.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("segment_leaf_outer_authority_v2.zig");
const input_provider_authority =
    @import("segment_publication_input_provider_authority_v2.zig");

const BundleV2 = bundle_mod.BundleForManifest(
    fixture_mod.DIMENSIONS,
    manifest_mod,
);
const AdaptersV2 = bundle_mod.AdaptersForManifest(manifest_mod);
const PAIR_FIXTURE_CORE_CALL_COUNT: usize = 16_852;
const PAIR_FIXTURE_TOTAL_CALL_COUNT: usize = 17_751;
const PAIR_FIXTURE_PROVIDER_LOG_SIZE: u32 = 15;

const test_support = @import("binary_fri_outer_bundle_v2_test_support.zig");
const prepareVerifierCoreCalls = test_support.prepareVerifierCoreCalls;
const OwnedRows = test_support.OwnedRows;
const OwnedManifestTree = test_support.OwnedManifestTree;
const fixtureManifestForCore = test_support.fixtureManifestForCore;
const expectSingleProviderSelector = test_support.expectSingleProviderSelector;
const expectExactProviderRows = test_support.expectExactProviderRows;
const expectCallSlicesEqual = test_support.expectCallSlicesEqual;
const expectAllCoreDomainAudits = test_support.expectAllCoreDomainAudits;
const expectGeometry = test_support.expectGeometry;
const fixtureManifest = test_support.fixtureManifest;
const fixtureLogSizes = test_support.fixtureLogSizes;
const boundaryComponents = test_support.boundaryComponents;
const fixtureCalls = test_support.fixtureCalls;
const nativeDigest = test_support.nativeDigest;
const shaDigest = test_support.shaDigest;

test "V2 rows 18 through 34 bind the exact typed manifest geometries" {
    const logs = fixtureLogSizes();
    const manifest = try fixtureManifest(logs);
    try manifest.validate();

    try expectGeometry(
        &manifest,
        .vm_air_composition_input,
        AdaptersV2.CompositionInput.manifestGeometry(
            .vm_air_composition_input,
            logs[18],
        ),
    );
    try expectGeometry(
        &manifest,
        .vm_air_composition_control,
        AdaptersV2.CompositionControl.manifestGeometry(
            .vm_air_composition_control,
            logs[19],
        ),
    );
    try expectGeometry(
        &manifest,
        .query_bits,
        AdaptersV2.QueryBits.manifestGeometry(.query_bits, logs[20]),
    );
    try expectGeometry(
        &manifest,
        .query_mapping,
        AdaptersV2.QueryMapping.manifestGeometry(.query_mapping, logs[21]),
    );
    try expectGeometry(
        &manifest,
        .merkle_root,
        AdaptersV2.MerkleRoot.manifestGeometry(.merkle_root, logs[22]),
    );
    try expectGeometry(
        &manifest,
        .trace_merkle,
        AdaptersV2.TraceMerkle.manifestGeometry(.trace_merkle, logs[23]),
    );
    try expectGeometry(
        &manifest,
        .pcs_deep_input,
        AdaptersV2.Pcs.manifestGeometry(.pcs_deep_input, logs[24]),
    );
    try expectGeometry(
        &manifest,
        .fri_merkle_leaf,
        AdaptersV2.FriLeaf.manifestGeometry(.fri_merkle_leaf, logs[25]),
    );
    try expectGeometry(
        &manifest,
        .fri_merkle_node,
        AdaptersV2.FriNode.manifestGeometry(.fri_merkle_node, logs[26]),
    );
    try expectGeometry(
        &manifest,
        .fri_merkle_anchor,
        AdaptersV2.FriAnchor.manifestGeometry(.fri_merkle_anchor, logs[27]),
    );
    try expectGeometry(
        &manifest,
        .fri_verifier_control,
        AdaptersV2.FriControl.manifestGeometry(
            .fri_verifier_control,
            logs[28],
        ),
    );
    try expectGeometry(
        &manifest,
        .fri_verifier_input,
        AdaptersV2.FriInput.manifestGeometry(.fri_verifier_input, logs[29]),
    );
    try expectGeometry(
        &manifest,
        .qm31_mul,
        AdaptersV2.Multiply.manifestGeometry(.qm31_mul, logs[30]),
    );
    try expectGeometry(
        &manifest,
        .qm31_inv,
        AdaptersV2.Inverse.manifestGeometry(.qm31_inv, logs[31]),
    );
    try expectGeometry(
        &manifest,
        .linear_ops,
        AdaptersV2.Linear.manifestGeometry(.linear_ops, logs[32]),
    );
    try expectGeometry(
        &manifest,
        .merkle_path,
        AdaptersV2.MerklePath.manifestGeometry(.merkle_path, logs[33]),
    );
    try expectGeometry(
        &manifest,
        .poseidon2,
        AdaptersV2.Poseidon2.manifestGeometry(logs[34]),
    );

    var mask: u64 = 0;
    for (18..35) |row| {
        const placement = manifest.placements[row] orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(u8, @intCast(row)), placement.geometry.roster_row);
        try std.testing.expectEqual(@as(u8, @intCast(row)), placement.claimed_sum_index);
        mask |= @as(u64, 1) << @intCast(row);
    }
    try std.testing.expectEqual(cohort_mod.CORE_ROWS_MASK, mask);
}

test "native schedule receipt completes 885 plus 14 with exactly 294 calls" {
    // Receipt-level schedule coverage only. These synthetic calls pin the
    // native SegmentV2 protocol profile; they are not evidence emitted by the
    // binary-pair source exercised below.
    const boundary_count = cohort_mod.MEASURED_TRANSCRIPT_POSEIDON_CALLS +
        cohort_mod.MEASURED_AUTHORITY_POSEIDON_CALLS;
    const total_count = boundary_count + cohort_mod.MEASURED_CORE_POSEIDON_CALLS;
    try std.testing.expectEqual(
        cohort_mod.MEASURED_TOTAL_POSEIDON_CALLS,
        total_count,
    );

    const calls = try fixtureCalls(std.testing.allocator, total_count);
    defer std.testing.allocator.free(calls);
    const boundary = try schedule_mod.SharedPoseidonCallLayoutV2
        .initBoundaryPrefix(
        cohort_mod.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        cohort_mod.MEASURED_AUTHORITY_POSEIDON_CALLS,
        calls[0..boundary_count],
    );
    var completed = try schedule_mod.OwnedCompletePoseidonScheduleV2.init(
        std.testing.allocator,
        &boundary,
        calls[0..boundary_count],
        calls[boundary_count..],
    );
    defer completed.deinit();
    try completed.validateAgainst(&boundary, calls[0..boundary_count]);
    try std.testing.expectEqual(
        @as(usize, cohort_mod.MEASURED_CORE_POSEIDON_CALLS),
        try completed.layout.verifier_core.count(),
    );
    try std.testing.expectEqual(
        @as(usize, cohort_mod.MEASURED_TOTAL_POSEIDON_CALLS),
        completed.calls.len,
    );
    try std.testing.expectEqual(@as(usize, 1), schedule_mod.PROVIDER_INSTANCE_COUNT);
    try std.testing.expectEqual(@as(u8, 34), schedule_mod.PROVIDER_COMPONENT_INDEX);

    // The copied prefix is immutable custody, not merely equal-length input.
    completed.calls[boundary_count - 1].input[0] +%= 1;
    try std.testing.expectError(
        error.CallLayoutMismatch,
        completed.validateAgainst(&boundary, calls[0..boundary_count]),
    );
}

test "V2 bundle public contract is allocation-free on all hot tree writers" {
    inline for (.{
        "initWithSharedScheduleV2",
        "fillPreprocessedInto",
        "fillMainInto",
        "fillInteractionInto",
        "validateGeneratedInteractions",
        "auditGeneratedInteractions",
        "initComponents",
    }) |name| try std.testing.expect(@hasDecl(BundleV2, name));
    try std.testing.expectEqual(@as(usize, 17), bundle_mod.ROW_COUNT);
    try std.testing.expectEqual(@as(u8, 18), bundle_mod.FIRST_ROW);
    try std.testing.expectEqual(@as(u8, 34), bundle_mod.LAST_ROW);
    try std.testing.expectEqual(
        [_]usize{0} ** manifest_mod.TREE_COUNT,
        bundle_mod.HOT_TREE_HEAP_ALLOCATIONS,
    );
    try std.testing.expectEqual(@as(usize, 0), bundle_mod.HOT_ALL_TREES_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 0), bundle_mod.ROW34_REPLAYED_SCALAR_PERMUTATIONS);
}

test "V2 binary-pair owner fills all trees and audits one complete provider" {
    const allocator = std.testing.allocator;
    var fixture = try source_test_support.Fixture.initFull(allocator);
    defer fixture.deinit();

    const core_calls = try prepareVerifierCoreCalls(allocator, &fixture.source);
    defer allocator.free(core_calls);
    try std.testing.expectEqual(
        PAIR_FIXTURE_CORE_CALL_COUNT,
        core_calls.len,
    );

    // A valid native-segment receipt is not a valid binary-pair receipt. The
    // constructor knows the pair workspace's exact core-call cardinality and
    // rejects this profile confusion before allocating the full provider.
    const native_calls = try fixtureCalls(
        allocator,
        cohort_mod.MEASURED_TOTAL_POSEIDON_CALLS,
    );
    defer allocator.free(native_calls);
    const native_layout = try schedule_mod.SharedPoseidonCallLayoutV2.initComplete(
        cohort_mod.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        cohort_mod.MEASURED_AUTHORITY_POSEIDON_CALLS,
        cohort_mod.MEASURED_CORE_POSEIDON_CALLS,
        native_calls,
    );
    if (BundleV2.initWithSharedScheduleV2(
        allocator,
        &fixture.source,
        &native_layout,
        native_calls,
    )) |unexpected_value| {
        var unexpected = unexpected_value;
        unexpected.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(
        error.ProviderIdentityMismatch,
        err,
    );

    const boundary_call_count = cohort_mod.MEASURED_TRANSCRIPT_POSEIDON_CALLS +
        cohort_mod.MEASURED_AUTHORITY_POSEIDON_CALLS;
    const boundary_calls = try fixtureCalls(allocator, boundary_call_count);
    defer allocator.free(boundary_calls);
    const boundary_layout = try schedule_mod.SharedPoseidonCallLayoutV2
        .initBoundaryPrefix(
        cohort_mod.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        cohort_mod.MEASURED_AUTHORITY_POSEIDON_CALLS,
        boundary_calls,
    );
    var schedule = try schedule_mod.OwnedCompletePoseidonScheduleV2.init(
        allocator,
        &boundary_layout,
        boundary_calls,
        core_calls,
    );
    defer schedule.deinit();
    try std.testing.expectEqual(
        PAIR_FIXTURE_TOTAL_CALL_COUNT,
        schedule.calls.len,
    );

    var allocation_meter = std.testing.FailingAllocator.init(allocator, .{});
    const measured_allocator = allocation_meter.allocator();
    var bundle = try BundleV2.initWithSharedScheduleV2(
        measured_allocator,
        &fixture.source,
        &schedule.layout,
        schedule.calls,
    );
    defer bundle.deinit();
    try std.testing.expectEqual(
        bundle_mod.ProviderCustody.complete_shared_schedule_v2,
        bundle.providerCustody(),
    );
    const receipt = bundle.sharedScheduleReceipt() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualDeep(schedule.layout, receipt);

    const component_logs = try bundle.componentLogSizes();
    try std.testing.expectEqual(
        PAIR_FIXTURE_PROVIDER_LOG_SIZE,
        component_logs[16],
    );
    const manifest = try fixtureManifestForCore(component_logs);
    var tree0 = try OwnedManifestTree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer tree0.deinit();
    var tree1 = try OwnedManifestTree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer tree1.deinit();
    var tree2 = try OwnedManifestTree.init(
        allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer tree2.deinit();

    // Destination shape, freshness, and alias failures happen before the
    // first trace write and preserve every caller-owned word.
    try std.testing.expectError(
        error.InvalidTraceShape,
        bundle.fillPreprocessedInto(
            &manifest,
            tree0.columns[0 .. tree0.columns.len - 1],
        ),
    );
    try std.testing.expect(tree0.allZero());
    const row18 = manifest.placements[18].?;
    const first_owned: usize = row18.preprocessed_offset;
    const second_owned = first_owned + 1;
    try std.testing.expect(row18.geometry.preprocessed_columns >= 2);
    const saved_second = tree0.columns[second_owned];
    tree0.columns[second_owned] = tree0.columns[first_owned];
    try std.testing.expectError(
        error.DestinationAlias,
        bundle.fillPreprocessedInto(&manifest, tree0.columns),
    );
    tree0.columns[second_owned] = saved_second;
    try std.testing.expect(tree0.allZero());
    tree0.columns[first_owned][0] = M31.one();
    try std.testing.expectError(
        error.DestinationNotZero,
        bundle.fillPreprocessedInto(&manifest, tree0.columns),
    );
    try std.testing.expectEqual(@as(usize, 1), tree0.nonZeroCount());
    tree0.columns[first_owned][0] = M31.zero();

    const original_source_allocator = fixture.source.allocator;
    fixture.source.allocator = measured_allocator;
    defer fixture.source.allocator = original_source_allocator;
    const hot_allocation_start = allocation_meter.alloc_index;
    try bundle.fillPreprocessedInto(&manifest, tree0.columns);
    try std.testing.expect(tree0.anyNonZero());
    try expectSingleProviderSelector(&tree0, &manifest);

    // The bundle borrows the authenticated schedule. Corrupting its core
    // suffix after construction must reject Tree 1 and clear all 17 rows,
    // while leaving the bundle retryable once custody is restored.
    const core_start: usize = schedule.layout.verifier_core.start;
    const original_core_word = schedule.calls[core_start].input[0];
    schedule.calls[core_start].input[0] +%= 1;
    try std.testing.expectError(
        error.ProviderIdentityMismatch,
        bundle.fillMainInto(&manifest, tree1.columns),
    );
    try std.testing.expect(tree1.allZero());
    schedule.calls[core_start].input[0] = original_core_word;

    try bundle.fillMainInto(&manifest, tree1.columns);
    try std.testing.expect(tree1.anyNonZero());
    try expectExactProviderRows(
        &tree1,
        &manifest,
        PAIR_FIXTURE_TOTAL_CALL_COUNT,
    );
    const prepared_core = try bundle.verifierCoreCallsPrepared();
    const prepared_complete = try bundle.completeProviderCallsPrepared();
    try expectCallSlicesEqual(core_calls, prepared_core);
    try expectCallSlicesEqual(schedule.calls, prepared_complete);
    try expectCallSlicesEqual(
        prepared_core,
        prepared_complete[core_start..schedule.layout.verifier_core.end],
    );

    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations
        .init(&relations);

    // Tree 2 has the same fail-atomic custody guarantee, even though its 16
    // typed rows are generated before the row-34 provider is reached.
    schedule.calls[core_start].input[0] +%= 1;
    try std.testing.expectError(
        error.ProviderIdentityMismatch,
        bundle.fillInteractionInto(
            &manifest,
            &relations,
            &provider_relations,
            tree2.columns,
        ),
    );
    try std.testing.expect(tree2.allZero());
    schedule.calls[core_start].input[0] = original_core_word;

    const generated = try bundle.fillInteractionInto(
        &manifest,
        &relations,
        &provider_relations,
        tree2.columns,
    );
    try std.testing.expect(tree2.anyNonZero());
    try std.testing.expectEqual(
        hot_allocation_start,
        allocation_meter.alloc_index,
    );
    try generated.validateAgainst(&bundle, &relations, &provider_relations);

    const row_claims = generated.claims.asRows18Through34();
    var claims = try manifest_mod.ClaimVector.init(&manifest);
    for (row_claims, 18..) |claim, row|
        try claims.bind(@enumFromInt(row), claim);
    try std.testing.expectEqual(cohort_mod.CORE_ROWS_MASK, claims.bound_mask);
    try std.testing.expectError(error.ClaimMissing, claims.sealClaims(&manifest));

    const audited = try bundle.auditGeneratedInteractions(
        allocator,
        &relations,
        &provider_relations,
        &generated,
    );
    try audited.validateAgainst(&bundle, &relations, &provider_relations);
    try expectAllCoreDomainAudits(audited.audits, generated.claims);

    var components = try bundle.initComponents(
        &manifest,
        &relations,
        &provider_relations,
        &generated,
    );
    _ = &components;

    var stale = generated;
    stale.claims.poseidon2_partials[0] =
        stale.claims.poseidon2_partials[0].add(QM31.one());
    try std.testing.expectError(
        error.GeneratedIdentityMismatch,
        stale.validateAgainst(&bundle, &relations, &provider_relations),
    );

    var forged_typed = generated;
    forged_typed.claims.typed_rows[0] =
        forged_typed.claims.typed_rows[0].add(QM31.one());
    forged_typed.identity = forged_typed.identityDigest();
    try forged_typed.validateAgainst(&bundle, &relations, &provider_relations);
    try std.testing.expectError(
        error.ClaimMismatch,
        bundle.auditGeneratedInteractions(
            allocator,
            &relations,
            &provider_relations,
            &forged_typed,
        ),
    );

    var forged_provider = generated;
    std.mem.swap(
        QM31,
        &forged_provider.claims.poseidon2_partials[0],
        &forged_provider.claims.poseidon2_partials[1],
    );
    forged_provider.identity = forged_provider.identityDigest();
    try forged_provider.validateAgainst(&bundle, &relations, &provider_relations);
    try std.testing.expectError(
        error.ProviderClaimMismatch,
        bundle.auditGeneratedInteractions(
            allocator,
            &relations,
            &provider_relations,
            &forged_provider,
        ),
    );
}
