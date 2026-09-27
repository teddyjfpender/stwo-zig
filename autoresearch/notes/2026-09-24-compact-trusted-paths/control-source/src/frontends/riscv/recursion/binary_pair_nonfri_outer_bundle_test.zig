//! End-to-end custody, composition, mutation, and performance gates for the
//! binary non-FRI rows 0--17/35 bundle.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const bundle_mod = @import("binary_pair_nonfri_outer_bundle.zig");
const pair_authority = @import("binary_pair_authority.zig");
const pair_fixture_mod = @import("binary_pair_test_fixture.zig");
const transcript_source_mod = @import("binary_transcript_outer_source.zig");
const statement_source = @import("outer_parent_statement_air_source.zig");
const statement_parent_source = @import("outer_parent_statement_source.zig");
const outer_transcript_source = @import("outer_parent_transcript_source.zig");
const statement_authority_mod = @import("segment_statement_outer_source.zig");
const admission = @import("outer_parent_child_admission.zig");
const outer_support = @import("outer_parent_transcript_source_test.zig");
const inactive_source_mod = @import("binary_inactive_outer_source.zig");
const public_authority_mod = @import("segment_public_outer_source.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const pair_node = @import("pair_node.zig");
const vm_claim = @import("vm_public_claim.zig");
const global_closure = @import("binary_global_closure_outer_source.zig");
const relation = @import("../air/lang/relation.zig");

const air = @import("air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const roster = air.universal_roster;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;

pub const TRANSCRIPT_DIMENSIONS = pair_fixture_mod.DIMENSIONS;
pub const STATEMENT_DIMENSIONS = outer_support.TEST_DIMENSIONS;
const PairPrepared = pair_authority.Prepared(TRANSCRIPT_DIMENSIONS);
const TranscriptSource = transcript_source_mod.Source(TRANSCRIPT_DIMENSIONS);
const StatementParent = statement_parent_source.Prepared(STATEMENT_DIMENSIONS);
const StatementPrepared = statement_source.Prepared(STATEMENT_DIMENSIONS);
const Bundle = bundle_mod.Bundle(TRANSCRIPT_DIMENSIONS, STATEMENT_DIMENSIONS);

const test_support = @import("binary_pair_nonfri_outer_bundle_test_support.zig");
pub const Fixture = test_support.Fixture;
const alignPairVerificationKey = test_support.alignPairVerificationKey;
const bindingFor = test_support.bindingFor;
const authorityFromBindings = test_support.authorityFromBindings;
const Tree = test_support.Tree;
const treeColumnCount = test_support.treeColumnCount;
const treeOffset = test_support.treeOffset;
const geometryColumnCount = test_support.geometryColumnCount;
const ownedRow = test_support.ownedRow;
const expectOwnedTreeZero = test_support.expectOwnedTreeZero;
const expectOwnedTreeHasData = test_support.expectOwnedTreeHasData;
const expectUnownedTreeZero = test_support.expectUnownedTreeZero;

test "binary non-FRI bundle admits two independently authenticated source paths" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const bundle = try fixture.bundle();
    try bundle.validate();
    try std.testing.expectEqual(@as(usize, 0), bundle_mod.FIRST_PREFIX_ROW);
    try std.testing.expectEqual(@as(usize, 18), bundle_mod.PREFIX_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 35), bundle_mod.SHARED_PROVIDER_ROW);
    try std.testing.expect(!bundle_mod.WHOLE_FRONTEND_VERIFIED);
    try std.testing.expect(!bundle_mod.COMPLETE_PARENT_STARK_VERIFIED);
    try std.testing.expect(!bundle_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!bundle_mod.VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED);
    try std.testing.expectEqual(
        @as(usize, 1),
        bundle_mod.HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE,
    );
    try std.testing.expectEqual(
        @as(usize, 22),
        bundle_mod.HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        bundle_mod.HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        bundle_mod.HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE,
    );
    try std.testing.expectEqual(
        @as(usize, 19),
        bundle_mod.HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE,
    );

    var logs = [_]u32{0} ** roster.COMPONENT_COUNT;
    bundle.installLogSizes(&logs);
    for (logs[0..bundle_mod.PREFIX_ROW_COUNT]) |log_size|
        try std.testing.expect(log_size != 0);
    try std.testing.expectEqual(
        statement_source.RANGE_CHECK_LOG_SIZE,
        logs[bundle_mod.SHARED_PROVIDER_ROW],
    );
    for (logs[18..35]) |log_size| try std.testing.expectEqual(@as(u32, 0), log_size);

    const lanes = bundle.loweringLanes();
    try std.testing.expectEqual(@as(usize, 1), lanes.len);
    try std.testing.expectEqual(
        statement_source.STATEMENT_CIRCUIT_ID,
        lanes[0].circuit_id,
    );
    try lanes[0].graph.validate();
}

test "binary non-FRI bundle fills, audits, and exposes its exact ordered cohort" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const bundle = try fixture.bundle();
    const manifest = try fixture.manifest(&bundle);
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );

    var preprocessed = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    var main = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    var interaction = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();

    // Count only the three retained writers. All authorities, scratch, and
    // destination storage have crossed the cold boundary before this meter.
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const measured_allocator = measured.allocator();
    const saved_transcript_allocator = fixture.transcript_source.allocator;
    const saved_statement_allocator = fixture.statement_workspace.allocator;
    const saved_inactive_allocator = fixture.inactive_source.allocator;
    var allocators_restored = false;
    defer if (!allocators_restored) {
        fixture.inactive_source.allocator = saved_inactive_allocator;
        fixture.statement_workspace.allocator = saved_statement_allocator;
        fixture.transcript_source.allocator = saved_transcript_allocator;
    };
    fixture.transcript_source.allocator = measured_allocator;
    fixture.statement_workspace.allocator = measured_allocator;
    fixture.inactive_source.allocator = measured_allocator;

    try bundle.fillPreprocessedInto(&manifest, preprocessed.columns);
    try std.testing.expectEqual(
        bundle_mod.HOT_TREE_HEAP_ALLOCATIONS[0],
        measured.alloc_index,
    );
    try bundle.fillMainInto(&manifest, main.columns);
    try std.testing.expectEqual(
        bundle_mod.HOT_TREE_HEAP_ALLOCATIONS[0] +
            bundle_mod.HOT_TREE_HEAP_ALLOCATIONS[1],
        measured.alloc_index,
    );
    const generated = try bundle.fillInteractionInto(
        &manifest,
        &relations,
        &provider_relations,
        interaction.columns,
    );
    try std.testing.expectEqual(
        bundle_mod.HOT_ALL_TREES_HEAP_ALLOCATIONS,
        measured.alloc_index,
    );
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);

    fixture.inactive_source.allocator = saved_inactive_allocator;
    fixture.statement_workspace.allocator = saved_statement_allocator;
    fixture.transcript_source.allocator = saved_transcript_allocator;
    allocators_restored = true;

    try generated.validateAgainst(&bundle);
    const audited = try bundle.auditGeneratedInteractions(
        &relations,
        &provider_relations,
        &generated,
        null,
    );
    try audited.validateAgainst(&bundle);

    try expectOwnedTreeHasData(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );
    try expectOwnedTreeHasData(
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
        main.columns,
    );
    try expectOwnedTreeHasData(
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        interaction.columns,
    );
    try expectUnownedTreeZero(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );
    try expectUnownedTreeZero(
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
        main.columns,
    );
    try expectUnownedTreeZero(
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        interaction.columns,
    );

    const prefix_values = generated.claims.prefixValues();
    const prefix_audits = audited.audits.prefixValues();
    for (audited.prefix_rows, prefix_values, prefix_audits, 0..) |
        row_claim,
        claim,
        audit,
        row,
    | {
        try std.testing.expectEqual(@as(u8, @intCast(row)), @intFromEnum(row_claim.row));
        try std.testing.expect(row_claim.claimed_sum.eql(claim));
        try std.testing.expect(audit.total.eql(claim));
        for (row_claim.domains, audit.values, 0..) |domain_claim, value, domain| {
            try std.testing.expectEqual(
                @as(u8, @intCast(domain)),
                @intFromEnum(domain_claim.domain),
            );
            try std.testing.expectEqual(
                @as(u8, @intFromBool(!value.isZero())),
                domain_claim.active,
            );
            try std.testing.expect(domain_claim.value.eql(value));
        }
    }
    try std.testing.expectEqual(
        global_closure.PROVIDER_ROW,
        audited.provider_claim.row,
    );
    try std.testing.expectEqual(
        global_closure.PROVIDER_DOMAIN,
        audited.provider_claim.domain,
    );
    try std.testing.expect(std.mem.eql(
        u8,
        &audited.provider_claim.source_authority_id,
        &fixture.statement_prepared.range.source_authority_digest,
    ));
    try std.testing.expect(std.mem.eql(
        u8,
        &audited.provider_claim.snapshot_id,
        &fixture.statement_prepared.range.provider().authority_digest,
    ));
    try std.testing.expect(
        audited.audits.sharedProviderRequestContribution()
            .add(audited.provider_claim.claimed_sum).isZero(),
    );
    try std.testing.expect(
        audited.audits.sharedProviderRequestContribution().eql(
            generated.claims.sharedProviderRequestContribution(),
        ),
    );

    var claim_vector = try manifest_mod.ClaimVector.init(&manifest);
    try generated.claims.bindPrefixInto(&claim_vector);
    const prefix_mask = (@as(u64, 1) << bundle_mod.PREFIX_ROW_COUNT) - 1;
    try std.testing.expectEqual(prefix_mask, claim_vector.bound_mask);
    try generated.claims.bindSharedProviderInto(&claim_vector);
    try std.testing.expectEqual(
        prefix_mask | (@as(u64, 1) << bundle_mod.SHARED_PROVIDER_ROW),
        claim_vector.bound_mask,
    );

    const components = try bundle.initComponents(
        &manifest,
        &relations,
        &provider_relations,
        &generated,
    );
    // These accesses intentionally pin the public integration surface: the
    // all-36 recorder never reconstructs a claim or reaches into a source.
    _ = components.transcript.control;
    _ = components.statement.statement_input;
    _ = components.inactive.public_logup_control;
    _ = components.statement.range_check;
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try components.appendPrefixToGate(&manifest, &gate);
    try std.testing.expectEqual(@as(u8, bundle_mod.PREFIX_ROW_COUNT), gate.count);
    try std.testing.expectError(
        error.AdapterOrderMismatch,
        components.appendSharedProviderToGate(&manifest, &gate),
    );
    try std.testing.expectEqual(@as(u8, bundle_mod.PREFIX_ROW_COUNT), gate.count);

    var stale_bundle = bundle;
    stale_bundle.authority_seal[0] ^= 1;
    try std.testing.expectError(error.BundleIdentityMismatch, stale_bundle.validate());

    var stale_generated = generated;
    stale_generated.identity[0] ^= 1;
    try std.testing.expectError(
        error.GeneratedIdentityMismatch,
        stale_generated.validateAgainst(&bundle),
    );
    var stale_snapshot = generated;
    stale_snapshot.provider_snapshot_id[0] ^= 1;
    try std.testing.expectError(
        error.ProviderSnapshotMismatch,
        stale_snapshot.validateAgainst(&bundle),
    );
    var stale_provider = generated;
    stale_provider.provider_source_authority_id[0] ^= 1;
    try std.testing.expectError(
        error.ProviderAuthorityMismatch,
        stale_provider.validateAgainst(&bundle),
    );

    var stale_audited = audited;
    stale_audited.identity[0] ^= 1;
    try std.testing.expectError(
        error.AuditIdentityMismatch,
        stale_audited.validateAgainst(&bundle),
    );
    var detached_provider = audited;
    detached_provider.provider_claim.claimed_sum =
        detached_provider.provider_claim.claimed_sum.add(QM31.one());
    try std.testing.expectError(
        error.InvalidProviderClaimIdentity,
        detached_provider.validateAgainst(&bundle),
    );

    // Even a correction confined to the authorized range domain cannot mint
    // a new row-35 claim: the audited request contribution remains fixed by
    // rows 0--17, independently of the detached Claims convenience scalar.
    var forged_audits = audited.audits;
    var forged_claims = generated.claims;
    const range_domain = @intFromEnum(relation.Domain.range_check_8_8);
    const delta = QM31.one();
    forged_audits.statement.range_check.values[range_domain] =
        forged_audits.statement.range_check.values[range_domain].add(delta);
    forged_audits.statement.range_check.total =
        forged_audits.statement.range_check.total.add(delta);
    forged_claims.statement.range_check =
        forged_claims.statement.range_check.add(delta);
    forged_claims.statement.range_requests =
        forged_claims.statement.range_requests.sub(delta);
    try std.testing.expectError(
        error.AuditClaimMismatch,
        forged_audits.validateAgainst(forged_claims),
    );
    try std.testing.expectError(
        error.VerifierAuditCustodyUnavailable,
        bundle_mod.VerifierDomainAuditAdapterV1.admit(),
    );
}

test "binary non-FRI bundle rejects left and right authority substitution" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const bundle = try fixture.bundle();

    var left_substituted_parent = fixture.statement_parent;
    left_substituted_parent.transcript.children[0] =
        fixture.statement_parent.transcript.children[1];
    var left_substituted = bundle;
    left_substituted.inputs.statement_parent = &left_substituted_parent;
    try std.testing.expectError(
        error.CrossCustodyMismatch,
        left_substituted.validate(),
    );

    var right_substituted_parent = fixture.statement_parent;
    right_substituted_parent.transcript.children[1] =
        fixture.statement_parent.transcript.children[0];
    var right_substituted = bundle;
    right_substituted.inputs.statement_parent = &right_substituted_parent;
    try std.testing.expectError(
        error.CrossCustodyMismatch,
        right_substituted.validate(),
    );

    var swapped_parent = fixture.statement_parent;
    std.mem.swap(
        @TypeOf(swapped_parent.transcript.children[0]),
        &swapped_parent.transcript.children[0],
        &swapped_parent.transcript.children[1],
    );
    var swapped = bundle;
    swapped.inputs.statement_parent = &swapped_parent;
    try std.testing.expectError(error.CrossCustodyMismatch, swapped.validate());
}

test "binary non-FRI bundle rejects aliases and rolls back a late source failure" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const bundle = try fixture.bundle();
    const manifest = try fixture.manifest(&bundle);

    var preprocessed = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    var stale_manifest = manifest;
    stale_manifest.seal[0] ^= 1;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        bundle.fillPreprocessedInto(&stale_manifest, preprocessed.columns),
    );
    try expectOwnedTreeZero(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );

    const owned_placement = try manifest.placement(.control);
    const unowned_row: roster.Component = @enumFromInt(bundle_mod.PREFIX_ROW_COUNT);
    const unowned_placement = try manifest.placement(unowned_row);
    try std.testing.expect(owned_placement.geometry.preprocessed_columns != 0);
    try std.testing.expect(unowned_placement.geometry.preprocessed_columns != 0);
    const owned_index: usize = owned_placement.preprocessed_offset;
    const unowned_index: usize = unowned_placement.preprocessed_offset;
    const saved_unowned = preprocessed.columns[unowned_index];
    preprocessed.columns[unowned_index] = preprocessed.columns[owned_index];
    try std.testing.expectError(
        error.DestinationAlias,
        bundle.fillPreprocessedInto(&manifest, preprocessed.columns),
    );
    preprocessed.columns[unowned_index] = saved_unowned;
    try expectOwnedTreeZero(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );

    preprocessed.columns[owned_index][0] = M31.one();
    try std.testing.expectError(
        error.DestinationNotZero,
        bundle.fillPreprocessedInto(&manifest, preprocessed.columns),
    );
    preprocessed.columns[owned_index][0] = M31.zero();

    // The inactive public source is last in bundle order. Its first staging
    // allocation therefore fails only after transcript and statement rows
    // have written; the bundle-wide errdefer must erase all nineteen rows.
    var main = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    try std.testing.expect(unowned_placement.geometry.main_columns != 0);
    const unowned_main: usize = unowned_placement.main_offset;
    const sentinel = M31.fromCanonical(0x5151);
    main.columns[unowned_main][0] = sentinel;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const saved_allocator = fixture.inactive_source.allocator;
    fixture.inactive_source.allocator = failing.allocator();
    defer fixture.inactive_source.allocator = saved_allocator;
    try std.testing.expectError(
        error.OutOfMemory,
        bundle.fillMainInto(&manifest, main.columns),
    );
    fixture.inactive_source.allocator = saved_allocator;
    try expectOwnedTreeZero(
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
        main.columns,
    );
    try std.testing.expect(main.columns[unowned_main][0].eql(sentinel));
}
