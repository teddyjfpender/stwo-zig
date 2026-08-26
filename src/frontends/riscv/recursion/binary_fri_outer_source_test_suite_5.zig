//! Focused shard of binary_fri_outer_source_test.zig; import that suite facade.

const dependency_0 = @import("binary_fri_outer_source_test_capture_fixture.zig");
const dependency_1 = @import("binary_fri_outer_source_test_fixture.zig");
const dependency_3 = @import("binary_fri_outer_source_test_validate_composition_input_base_rows.zig");

const Bundle = dependency_0.Bundle;
const Fixture = dependency_1.Fixture;
const ManifestTree = dependency_3.ManifestTree;
const QM31 = dependency_0.QM31;
const air = dependency_0.air;
const bundle_mod = dependency_0.bundle_mod;
const source_mod = dependency_0.source_mod;
const std = dependency_0.std;
const validateCompositionInputBaseRows = dependency_3.validateCompositionInputBaseRows;

test "R-015 neutral binary FRI bundle writes and audits rows 18--34" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.initFull(allocator);
    defer fixture.deinit();
    var allocation_meter = std.testing.FailingAllocator.init(allocator, .{});
    const measured_allocator = allocation_meter.allocator();
    var bundle = try Bundle.init(measured_allocator, &fixture.source);
    defer bundle.deinit();
    const cold_allocation_count = allocation_meter.alloc_index;
    const original_source_allocator = fixture.source.allocator;
    fixture.source.allocator = measured_allocator;
    defer fixture.source.allocator = original_source_allocator;

    try std.testing.expect(bundle_mod.PROTOCOL_SUBSTRATE_ONLY);
    try std.testing.expect(!bundle_mod.PRODUCTION_ACTIVATION);
    try std.testing.expectEqual(
        @as(usize, 0),
        bundle_mod.ROW34_REPLAYED_SCALAR_PERMUTATIONS,
    );

    fixture.source.source_authority_digest[0] ^= 1;
    try std.testing.expectError(error.SourceAuthorityMismatch, bundle.validate());
    fixture.source.source_authority_digest[0] ^= 1;
    try bundle.validate();

    const samples = @constCast(fixture.capture_children[0].capture.sampled_values);
    const original_sample = samples[0];
    samples[0] = original_sample.add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        bundle.validateAgainstAuthority(),
    );
    samples[0] = original_sample;
    try bundle.validateAgainstAuthority();

    var builder = air.universal_adapter_manifest.Builder{};
    try bundle.appendManifestGeometries(&builder);
    const manifest = try builder.seal();
    try std.testing.expectEqual(
        @as(u8, source_mod.ROW_COUNT),
        manifest.roster_count,
    );
    try std.testing.expectEqual(
        @as(u8, source_mod.FIRST_ROW),
        manifest.roster_rows[0],
    );
    try std.testing.expectEqual(
        @as(u8, source_mod.LAST_ROW),
        manifest.roster_rows[manifest.roster_count - 1],
    );

    var preprocessed = try ManifestTree.init(
        allocator,
        &manifest,
        air.universal_adapter_manifest.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    var main = try ManifestTree.init(
        allocator,
        &manifest,
        air.universal_adapter_manifest.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    var interaction = try ManifestTree.init(
        allocator,
        &manifest,
        air.universal_adapter_manifest.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();

    try bundle.fillPreprocessedInto(&manifest, preprocessed.columns);
    try bundle.fillMainInto(&manifest, main.columns);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const provider_relations = try air.universal_shared_provider
        .SharedProviderRelations.init(&relations);
    const generated = try bundle.fillInteractionInto(
        &manifest,
        &relations,
        &provider_relations,
        interaction.columns,
    );
    try std.testing.expectEqual(
        cold_allocation_count,
        allocation_meter.alloc_index,
    );
    try generated.validateAgainst(&bundle, &relations, &provider_relations);
    const audited = try bundle.independentlyRebuildAndValidate(
        allocator,
        &relations,
        &provider_relations,
        &generated,
    );
    try audited.validateAgainst(&bundle, &relations, &provider_relations);
    try std.testing.expect(preprocessed.anyNonZero());
    try std.testing.expect(main.anyNonZero());
    try std.testing.expect(interaction.anyNonZero());
    try std.testing.expect(generated.claims.poseidon2Total().eql(
        generated.claims.asRows18Through34()[source_mod.ROW_COUNT - 1],
    ));

    var components = try bundle.initComponents(
        &manifest,
        &relations,
        &provider_relations,
        &generated,
    );
    try validateCompositionInputBaseRows(
        &components.composition_input,
        bundle.relation_rows.composition_input,
        preprocessed.columns,
        main.columns,
        interaction.columns,
    );
    var gate = try air.universal_adapter_manifest.ProofGate.init(&manifest);
    try components.appendToGate(&manifest, &gate);
    try gate.sealGate(&manifest);
    try gate.validate(&manifest);
    try std.testing.expectEqual(manifest.roster_count, gate.count);

    var stale = generated;
    stale.claims.poseidon2_partials[0] =
        stale.claims.poseidon2_partials[0].add(QM31.one());
    try std.testing.expectError(
        error.GeneratedIdentityMismatch,
        stale.validateAgainst(&bundle, &relations, &provider_relations),
    );

    var swapped = generated;
    std.mem.swap(
        QM31,
        &swapped.claims.poseidon2_partials[0],
        &swapped.claims.poseidon2_partials[1],
    );
    swapped.identity = swapped.identityDigest();
    try swapped.validateAgainst(&bundle, &relations, &provider_relations);
    try std.testing.expectError(
        error.ProviderClaimMismatch,
        bundle.independentlyRebuildAndValidate(
            allocator,
            &relations,
            &provider_relations,
            &swapped,
        ),
    );

    var corrective = generated;
    corrective.claims.poseidon2_partials[0] =
        corrective.claims.poseidon2_partials[0].add(QM31.one());
    corrective.claims.poseidon2_partials[1] =
        corrective.claims.poseidon2_partials[1].sub(QM31.one());
    try std.testing.expect(corrective.claims.poseidon2Total().eql(
        generated.claims.poseidon2Total(),
    ));
    corrective.identity = corrective.identityDigest();
    try corrective.validateAgainst(&bundle, &relations, &provider_relations);
    try std.testing.expectError(
        error.ProviderClaimMismatch,
        bundle.independentlyRebuildAndValidate(
            allocator,
            &relations,
            &provider_relations,
            &corrective,
        ),
    );

    var rejected = try ManifestTree.init(
        allocator,
        &manifest,
        air.universal_adapter_manifest.INTERACTION_TREE_INDEX,
    );
    defer rejected.deinit();
    const original_output = bundle.merkle_workspace.poseidon_outputs[0][0];
    bundle.merkle_workspace.poseidon_outputs[0][0] = original_output ^ 1;
    try std.testing.expectError(
        error.WorkspaceAuthorityMismatch,
        bundle.fillInteractionInto(
            &manifest,
            &relations,
            &provider_relations,
            rejected.columns,
        ),
    );
    bundle.merkle_workspace.poseidon_outputs[0][0] = original_output;
    try std.testing.expect(rejected.allZero());

    const original_outputs = bundle.merkle_workspace.poseidon_outputs;
    bundle.merkle_workspace.poseidon_outputs = @as(
        [*][source_mod.POSEIDON2_PROVIDER_SAMPLE_COUNT]u32,
        @ptrCast(bundle.merkle_workspace.logical_rows.ptr),
    )[0..original_outputs.len];
    try std.testing.expectError(error.WorkspaceAuthorityMismatch, bundle.validate());
    bundle.merkle_workspace.poseidon_outputs = original_outputs;
    try bundle.validate();
}
