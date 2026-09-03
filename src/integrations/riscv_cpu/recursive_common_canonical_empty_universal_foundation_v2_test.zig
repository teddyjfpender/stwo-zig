const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const foundation =
    @import("recursive_common_canonical_empty_universal_foundation_v2.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;
const manifest_mod = air.universal_adapter_manifest;
const range_bridge = air.range_check_8_8_bridge;
const roster = air.universal_roster;
const universal = air.universal_challenges;

test "canonical-empty V2 foundation pins exact universal-36 geometry" {
    const authority = try foundation.ManifestAuthorityV2.build();
    try authority.validate();
    try std.testing.expectEqual(@as(u8, 36), authority.manifest.roster_count);
    try std.testing.expectEqual(
        @as(u32, 570),
        authority.manifest.total_preprocessed_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 1044),
        authority.manifest.total_main_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 560),
        authority.manifest.total_interaction_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 1312),
        authority.manifest.total_constraints,
    );
    for (authority.component_log_sizes, 0..) |log_size, row| {
        const expected: u32 = if (row ==
            @intFromEnum(roster.Component.range_check_8_8))
            range_bridge.LOG_SIZE
        else
            4;
        try std.testing.expectEqual(expected, log_size);
    }

    var changed = authority;
    changed.component_log_sizes[0] = 5;
    try std.testing.expectError(
        error.CanonicalUniversalManifestMismatch,
        changed.validate(),
    );
    changed = authority;
    changed.manifest.total_main_columns += 1;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        changed.validate(),
    );
}

test "canonical-empty V2 foundation materializes exact inactive witness" {
    var witness = try foundation.OwnedInactiveWitnessV2.create(
        std.testing.allocator,
    );
    defer witness.deinit();
    try witness.validate();
    try std.testing.expectEqual(
        @as(usize, foundation.PREPROCESSED_COLUMN_COUNT),
        witness.preprocessed.columns.len,
    );
    try std.testing.expectEqual(
        @as(usize, foundation.MAIN_COLUMN_COUNT),
        witness.main.columns.len,
    );
    try std.testing.expectEqual(
        @as(usize, foundation.INTERACTION_COLUMN_COUNT),
        witness.interaction.columns.len,
    );

    const poseidon = try witness.authority.manifest.placement(.poseidon2);
    const poseidon_selector = try witness.preprocessed.column(
        poseidon.preprocessed_offset,
    );
    const selected = stwo_core.utils.bitReverseIndex(
        stwo_core.utils.cosetIndexToCircleDomainIndex(
            0,
            poseidon.geometry.log_size,
        ),
        poseidon.geometry.log_size,
    );
    poseidon_selector[selected] = M31.zero();
    try std.testing.expectError(
        error.CanonicalInactiveWitnessMismatch,
        witness.validate(),
    );
    poseidon_selector[selected] = M31.one();
    try witness.validate();

    const first_main = try witness.main.column(0);
    first_main[0] = M31.one();
    try std.testing.expectError(
        error.CanonicalInactiveWitnessMismatch,
        witness.validate(),
    );
    first_main[0] = M31.zero();
    try witness.validate();

    const range = try witness.authority.manifest.placement(.range_check_8_8);
    const low = try witness.preprocessed.column(range.preprocessed_offset + 1);
    const table_row = range_bridge.committedRow(257);
    const prior = low[table_row];
    low[table_row] = M31.zero();
    try std.testing.expectError(
        error.CanonicalInactiveWitnessMismatch,
        witness.validate(),
    );
    low[table_row] = prior;
    try witness.validate();
}

test "canonical-empty V2 foundation owns and seals all 36 typed rows" {
    const relations = universal.UniversalRelations.dummy();
    var cohort = try foundation.InactiveCohortV2.create(
        std.testing.allocator,
        &relations,
    );
    defer cohort.deinit();
    try cohort.validate();

    var gate = try manifest_mod.ProofGate.init(&cohort.authority.manifest);
    try cohort.appendAndSealGate(&gate);
    try gate.validate(&cohort.authority.manifest);
    try std.testing.expectEqual(@as(u8, 36), gate.count);
    try std.testing.expect(gate.sealed);

    cohort.authority.component_log_sizes[0] += 1;
    try std.testing.expectError(
        error.CanonicalUniversalManifestMismatch,
        cohort.validate(),
    );
}

test "canonical-empty V2 foundation cannot mint output or cold geometry" {
    try std.testing.expectEqual(
        foundation.MissingAuthorityV2.recursive_node_public_v2_air_owner,
        foundation.firstMissingAuthority(),
    );
    try std.testing.expectError(
        error.FieldNativePublicOutputUnavailable,
        foundation.requirePublicOutputLane(),
    );
    try std.testing.expectError(
        error.ColdFixedProofShapeUnavailable,
        foundation.requireColdFixedProofShape(),
    );
    try std.testing.expect(!foundation.PRODUCTION_ACTIVATION);
    try std.testing.expect(!foundation.SHA_IN_RECURSIVE_AIR);
}
