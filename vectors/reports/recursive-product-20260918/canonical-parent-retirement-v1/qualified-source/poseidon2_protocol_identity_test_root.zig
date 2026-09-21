//! Focused canonical compact-Poseidon identity qualification.
// Keep the import reachable when selecting one named test with --test-filter.
test {
    _ = @import("air/memory_commitment/poseidon2_universal_identity_v2.zig");
    _ = @import("air/logup.zig");
    _ = @import("air/lang/typed_poseidon2_identity_test.zig");
    _ = @import("air/lang/typed_poseidon2_identity_codec.zig");
}

const std = @import("std");
const provider = @import("recursion/air/universal_shared_provider.zig");
const manifest_mod = @import("recursion/air/universal_adapter_manifest.zig");
const universal = @import("recursion/air/universal_challenges.zig");
const identity = @import("air/memory_commitment/poseidon2_universal_identity_v2.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const Canonical = provider.Poseidon2Degree3AdapterForManifest(manifest_mod);
const Compatible = provider.Poseidon2Degree3AdapterWithCompatibility(manifest_mod, .allow_reviewed_legacy);

fn manifestFor(geometry: manifest_mod.Geometry) !manifest_mod.Manifest {
    var builder = manifest_mod.Builder{};
    _ = try builder.append(geometry);
    return builder.seal();
}

test "canonical recursive provider admits new identities and explicit retained compact identities" {
    const relations = universal.UniversalRelations.dummy();
    const challenges = try provider.SharedProviderRelations.init(&relations);
    const claims = [_]QM31{ QM31.zero(), QM31.zero() };
    const current = try manifestFor(Canonical.manifestGeometry(4));
    var legacy_geometry = Canonical.manifestGeometry(4);
    legacy_geometry.semantic_digest = identity.LEGACY_SOURCE_DIGEST;
    const legacy = try manifestFor(legacy_geometry);
    const current_adapter = try Canonical.initWithAllocator(std.testing.allocator, &current, 4, 3, &challenges, &relations, claims);
    _ = try current_adapter.binding(&current);
    try std.testing.expectError(error.ProviderGeometryMismatch, Canonical.initWithAllocator(std.testing.allocator, &legacy, 4, 3, &challenges, &relations, claims));
    const retained_adapter = try Compatible.initWithAllocator(std.testing.allocator, &legacy, 4, 3, &challenges, &relations, claims);
    _ = try retained_adapter.binding(&legacy);
    const compatible_current = try Compatible.initWithAllocator(std.testing.allocator, &current, 4, 3, &challenges, &relations, claims);
    _ = try compatible_current.binding(&current);
    // Compatibility never rewrites the authenticated manifest or its seal.
    try std.testing.expect(!std.mem.eql(u8, &current.seal, &legacy.seal));
    try std.testing.expectError(error.ProviderGeometryMismatch, retained_adapter.binding(&current));
}

test "canonical recursive provider rejects forged identities geometry and borrowed challenge changes" {
    const relations = universal.UniversalRelations.dummy();
    var challenges = try provider.SharedProviderRelations.init(&relations);
    const claims = [_]QM31{ QM31.zero(), QM31.zero() };
    var geometry = Canonical.manifestGeometry(4);
    geometry.semantic_digest = identity.LEGACY_SOURCE_DIGEST;
    geometry.semantic_digest[0] ^= 1;
    const forged = try manifestFor(geometry);
    try std.testing.expectError(error.ProviderGeometryMismatch, Compatible.initWithAllocator(std.testing.allocator, &forged, 4, 3, &challenges, &relations, claims));
    geometry = Canonical.manifestGeometry(4);
    geometry.semantic_digest = identity.LEGACY_SOURCE_DIGEST;
    geometry.main_columns += 1;
    const wrong_shape = try manifestFor(geometry);
    try std.testing.expectError(error.ProviderGeometryMismatch, Compatible.initWithAllocator(std.testing.allocator, &wrong_shape, 4, 3, &challenges, &relations, claims));
    const current = try manifestFor(Canonical.manifestGeometry(4));
    try std.testing.expectError(error.ProviderGeometryMismatch, Compatible.initWithAllocator(std.testing.allocator, &current, 5, 3, &challenges, &relations, claims));
    try std.testing.expectError(error.ProviderTraceShapeMismatch, Compatible.initWithAllocator(std.testing.allocator, &current, 4, 17, &challenges, &relations, claims));
    var adapter = try Compatible.initWithAllocator(std.testing.allocator, &current, 4, 3, &challenges, &relations, claims);
    adapter.component.claims[0] = QM31.one();
    try std.testing.expectError(error.ChallengeBindingMismatch, adapter.binding(&current));
    adapter.component.claims[0] = QM31.zero();
    challenges.native.poseidon2.z = challenges.native.poseidon2.z.add(QM31.one());
    try std.testing.expectError(error.ChallengeBindingMismatch, adapter.binding(&current));
}

test "canonical parent preparation rejects retired identities and preserves admitted snapshots" {
    const prepared = try @import("recursion/detached_parent_prepared_v1.zig").testSnapshotAdmission();
    defer prepared.deinit();
}

test "parent definition owner releases partial construction on allocation failure" {
    const Definitions = @import("recursion/detached_parent_definitions_v1.zig").Definitions;
    // Exercise cleanup before and after completed definitions, including the
    // current multiplication definition and the shared range table contract.
    for ([_]usize{ 0, 1, 8, 32, 128, 512, 2048 }) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var definitions = Definitions.init(failing.allocator());
        defer definitions.deinit();
        const Setup = struct {
            fn run(owner: *Definitions) !void {
                try owner.initLogical(0);
                try owner.initLogical(1);
                try owner.initLogical(@import("recursion/detached_parent_components_v1.zig").logicalIndex(30));
                try owner.initRange();
            }
        };
        Setup.run(&definitions) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "parent collections agree on canonical geometry and reject retired AIR and identities" {
    const prepared = try @import("recursion/detached_parent_prepared_v1.zig").testSnapshotAdmission();
    defer prepared.deinit();
    const producer = @import("recursion/detached_parent_components_v1.zig");
    for (0..5) |variant| {
        var builder = manifest_mod.Builder{};
        for (prepared.manifest().roster_rows[0..prepared.manifest().roster_count]) |row| {
            var geometry = prepared.manifest().placements[row].?.geometry;
            if (row == 34 and variant == 1) geometry.semantic_digest = identity.LEGACY_SOURCE_DIGEST;
            if (row == 34 and variant == 2) geometry = provider.Poseidon2Adapter.manifestGeometry(geometry.log_size);
            if (row == 30 and variant == 3) {
                const legacy_entry = @import("recursion/air/universal_catalog_entry.zig").Entry{ .Air = @import("recursion/air/qm31_mul_full.zig"), .row = .qm31_mul, .requires_location = true };
                geometry = producer.Component(legacy_entry).manifestGeometry(.qm31_mul, geometry.log_size);
            }
            if (row == 34 and variant == 4) geometry.semantic_digest[0] ^= 1;
            _ = try builder.append(geometry);
        }
        const manifest = try builder.seal();
        var parameters = prepared.parameters();
        const legacy_parameters = [_]@import("stwo_core").fields.m31.M31{ .zero(), .zero(), .zero() };
        if (variant == 3) parameters.words[30] = &legacy_parameters;
        if (variant == 0) {
            try compareParentCollections(&manifest, parameters);
        } else {
            // A valid new seal is insufficient to admit an alternative AIR.
            try manifest.validate();
            try std.testing.expectError(error.DetachedParentManifestMismatch, parameters.validate(&manifest));
            const verifier = @import("recursion/detached_parent_verifier_components_v1.zig");
            const relations = universal.UniversalRelations.dummy();
            const claims = producer.ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
            try std.testing.expectError(error.DetachedParentManifestMismatch, producer.OwnedComponentsV1.init(std.testing.allocator, &manifest, parameters, &relations, claims));
            try std.testing.expectError(error.DetachedParentManifestMismatch, verifier.OwnedComponentsV1.init(std.testing.allocator, &manifest, parameters, &relations, claims));
        }
    }
}

fn compareParentCollections(manifest: *const manifest_mod.Manifest, parameters: @import("recursion/detached_parent_contract_v1.zig").ParametersV1) !void {
    const producer = @import("recursion/detached_parent_components_v1.zig");
    const verifier = @import("recursion/detached_parent_verifier_components_v1.zig");
    const relations = universal.UniversalRelations.dummy();
    const claims = producer.ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const full = try producer.OwnedComponentsV1.init(std.testing.allocator, manifest, parameters, &relations, claims);
    defer full.deinit();
    const pure = try verifier.OwnedComponentsV1.init(std.testing.allocator, manifest, parameters, &relations, claims);
    defer pure.deinit();
    const expected = try full.verifierComponents();
    const actual = try pure.verifierComponents();
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right| {
        try std.testing.expectEqual(left.nConstraints(), right.nConstraints());
        try std.testing.expectEqual(left.maxConstraintLogDegreeBound(), right.maxConstraintLogDegreeBound());
        const left_indices = try left.preprocessedColumnIndices(std.testing.allocator);
        defer std.testing.allocator.free(left_indices);
        const right_indices = try right.preprocessedColumnIndices(std.testing.allocator);
        defer std.testing.allocator.free(right_indices);
        try std.testing.expectEqualSlices(usize, left_indices, right_indices);
    }
}
