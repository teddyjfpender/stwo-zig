//! Focused mutation and ordering gates for the 39+2 SegmentV2 claim ABI.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_binary_composition_authority.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const air = recursion.air;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const boundary_air = recursion.segment_leaf_outer_air_v2;
const boundary_authority = recursion.segment_leaf_outer_authority_v2;
const catalog_mod = air.segment_outer_typed_catalog_v2;
const manifest_mod = air.segment_outer_adapter_manifest_v2;
const provider_authority =
    recursion.segment_publication_input_provider_authority_v2;
const range_bridge = air.range_check_8_8_bridge;
const roster = air.universal_roster;
const universal_manifest = air.universal_manifest;

test "SegmentV2 composition profile writes exact 39 plus 2 ABI without projection" {
    const manifest = try fixtureManifest();
    const profile = try subject.SegmentV2CompositionProfileV1.seal(
        &manifest,
        nativeDigest(401),
    );

    var claims = [_]QM31{QM31.zero()} **
        subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT;
    for (&claims, 0..) |*claim, index|
        claim.* = QM31.fromU32Unchecked(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
            @intCast(index + 4),
        );
    const partials = [subject.SEGMENT_V2_POSEIDON_PARTIAL_COUNT]QM31{
        QM31.fromU32Unchecked(101, 103, 107, 109),
        QM31.fromU32Unchecked(113, 127, 131, 137),
    };
    claims[subject.SEGMENT_V2_POSEIDON_ROSTER_ROW] =
        partials[0].add(partials[1]);

    var destination = [_]QM31{QM31.zero()} **
        subject.SEGMENT_V2_COMPOSITION_CLAIM_COUNT;
    try profile.writeClaimInputs(
        &manifest,
        &claims,
        &partials,
        &destination,
    );
    try std.testing.expectEqualDeep(
        claims,
        destination[0..subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT].*,
    );
    try std.testing.expectEqualDeep(
        partials,
        destination[subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT..].*,
    );
    try std.testing.expectError(
        error.LegacySegmentV2ProjectionForbidden,
        profile.requireLegacyV1Projection(&manifest),
    );
}

test "SegmentV2 composition profile rejects authority and input mutations atomically" {
    const manifest = try fixtureManifest();
    const profile = try subject.SegmentV2CompositionProfileV1.seal(
        &manifest,
        nativeDigest(509),
    );

    inline for (.{
        "format_version",
        "schema_version",
        "physical_claim_count",
        "universal_roster_count",
        "poseidon_partial_count",
        "composition_claim_count",
        "poseidon_roster_row",
    }) |field| {
        var malformed = profile;
        @field(malformed, field) +%= 1;
        try std.testing.expectError(
            error.InvalidSegmentV2CompositionProfile,
            malformed.validateAgainst(&manifest),
        );
    }
    var malformed = profile;
    malformed.proof_kind = .binary_node;
    try std.testing.expectError(
        error.InvalidSegmentV2CompositionProfile,
        malformed.validateAgainst(&manifest),
    );
    malformed = profile;
    malformed.air_program_id[0] = m31.Modulus;
    try std.testing.expectError(
        error.InvalidSegmentV2CompositionProfile,
        malformed.validateAgainst(&manifest),
    );
    malformed = profile;
    malformed.profile_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidSegmentV2CompositionProfile,
        malformed.validateAgainst(&manifest),
    );

    var claims = [_]QM31{QM31.zero()} **
        subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT;
    const partials = [subject.SEGMENT_V2_POSEIDON_PARTIAL_COUNT]QM31{
        QM31.one(),
        QM31.one(),
    };
    var destination = [_]QM31{QM31.fromU32Unchecked(17, 19, 23, 29)} **
        subject.SEGMENT_V2_COMPOSITION_CLAIM_COUNT;
    const before = destination;
    try std.testing.expectError(
        error.SegmentV2PoseidonPartialMismatch,
        profile.writeClaimInputs(
            &manifest,
            &claims,
            &partials,
            &destination,
        ),
    );
    try std.testing.expectEqualDeep(before, destination);

    claims[subject.SEGMENT_V2_POSEIDON_ROSTER_ROW] =
        partials[0].add(partials[1]);
    destination = before;
    const aliased_partials: *const [subject.SEGMENT_V2_POSEIDON_PARTIAL_COUNT]QM31 =
        @ptrCast(&destination[subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT]);
    destination[subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT] = partials[0];
    destination[subject.SEGMENT_V2_PHYSICAL_CLAIM_COUNT + 1] = partials[1];
    const aliased_before = destination;
    try std.testing.expectError(
        error.SegmentV2ClaimInputAlias,
        profile.writeClaimInputs(
            &manifest,
            &claims,
            aliased_partials,
            &destination,
        ),
    );
    try std.testing.expectEqualDeep(aliased_before, destination);
}

test "SegmentV2 composition profile joins the exact V3 descriptor authority" {
    const manifest = try fixtureManifest();
    const universal_authority = try universal_manifest.build(fixtureLogSizes());
    const air_program_ids = composition_v3.AirProgramIdsV3{
        .segment_leaf = nativeDigest(701),
        .binary_node = nativeDigest(709),
        .empty_leaf = nativeDigest(719),
    };
    const roster_v3 = try composition_v3.ProgramRosterV3.seal(.{
        .universal = &universal_authority,
        .segment = &manifest,
    }, air_program_ids);
    const profile = try subject.SegmentV2CompositionProfileV1.seal(
        &manifest,
        air_program_ids.segment_leaf,
    );
    try profile.validateAgainstV3Descriptor(
        &manifest,
        roster_v3.forKind(.segment_leaf).*,
    );

    const mismatched_ids = composition_v3.AirProgramIdsV3{
        .segment_leaf = nativeDigest(727),
        .binary_node = air_program_ids.binary_node,
        .empty_leaf = air_program_ids.empty_leaf,
    };
    const mismatched_roster = try composition_v3.ProgramRosterV3.seal(.{
        .universal = &universal_authority,
        .segment = &manifest,
    }, mismatched_ids);
    try std.testing.expectError(
        error.SegmentV2RecorderDescriptorMismatch,
        profile.validateAgainstV3Descriptor(
            &manifest,
            mismatched_roster.forKind(.segment_leaf).*,
        ),
    );
}

fn fixtureManifest() !manifest_mod.Manifest {
    const log_sizes = fixtureLogSizes();
    const catalog = try catalog_mod.build(log_sizes, boundaryComponents(8));
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = provider_authority.sourceAuthorityShaId(),
    });
}

fn fixtureLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{4} ** roster.COMPONENT_COUNT;
    result[0] = 5;
    result[1] = 6;
    result[5] = 7;
    result[11] = 8;
    result[12] = 5;
    result[13] = 4;
    result[14] = 4;
    result[15] = 6;
    result[16] = 5;
    result[17] = air.vm_public_logup_control_witness_v2.TRACE_LOG_SIZE;
    result[@intFromEnum(roster.Component.poseidon2)] = 11;
    result[@intFromEnum(roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    return result;
}

fn boundaryComponents(
    statement_log_size: u8,
) [boundary_authority.COMPONENT_COUNT]boundary_authority.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = boundary_authority.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) <<
                @intCast(statement_log_size - 1)) + 1,
            .trace_log_size = statement_log_size,
            .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
            .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary_authority.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary_authority.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary_authority.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary_authority.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
