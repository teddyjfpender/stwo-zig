const std = @import("std");

const lookup_physical_v2 =
    @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
const support = @import("../../../../../product_tree/recursion/ethereum_leaf_context_test_support.zig");
const subject = @import("stwo_riscv_recursion").ethereum_vm_air_profile_v2;

const SAMPLED_VALUE_COUNT: u32 = 317;
const MUL_LOOKUP_INDEX: usize = 19;

test "authenticated VM AIR ProfileV2 binds fixed program and narrow Poseidon as an explicit circuit" {
    const allocator = std.testing.allocator;
    const geometry = @import("stwo_riscv_rv32").recursion.vm_composition_base_geometry;
    const narrow = @import("stwo_riscv_memory").air.poseidon2_narrow_component;
    const program = @import("stwo_riscv_rv32").air.program.interaction;
    var statement = support.retainedSegmentZeroCore();
    var manifest = lookup_physical_v2.Manifest.native();
    var authenticated = try lookup_physical_v2.AuthenticatedStatement.init(&statement, &manifest);
    const legacy_samples = try geometry.expectedSampledValueCount(&statement, &manifest);
    var legacy = try subject.deriveAuthority(allocator, &statement, &manifest, &authenticated, legacy_samples);
    defer legacy.deinit();
    var explicit_legacy = try subject.deriveAuthorityWithCircuitProfile(allocator, &statement, &manifest, &authenticated, legacy_samples, .legacy_v4);
    defer explicit_legacy.deinit();
    try std.testing.expectEqualSlices(u8, &legacy.identity_digest, &explicit_legacy.identity_digest);

    for (statement.infra_descs[0..statement.n_infra]) |*descriptor| {
        if (descriptor.kind == .poseidon2)
            descriptor.n_columns = @import("stwo_riscv_memory").air.poseidon2_narrow_degree3.N_MAIN_COLUMNS;
    }
    authenticated = try lookup_physical_v2.AuthenticatedStatement.init(&statement, &manifest);
    try std.testing.expectError(error.InvalidColumnGeometry, geometry.expectedSampledValueCount(&statement, &manifest));
    const samples = try @import("stwo_riscv_rv32").recursion.vm_composition_sample_geometry.expectedSampledValueCountWithLayout(&statement, &manifest, .fixed_decoded_narrow);
    try std.testing.expectEqual(legacy_samples - 158, samples);
    try std.testing.expectError(error.MainColumnCountMismatch, subject.deriveAuthority(allocator, &statement, &manifest, &authenticated, samples));
    var fixed = try subject.deriveAuthorityWithCircuitProfile(allocator, &statement, &manifest, &authenticated, samples, .fixed_program_narrow_v1);
    defer fixed.deinit();
    try fixed.validateAuthority(allocator, &statement, &manifest, &authenticated);
    try std.testing.expectEqual(subject.CIRCUIT_SCHEMA_VERSION, fixed.schema_version);
    try std.testing.expect(!std.mem.eql(u8, &legacy.identity_digest, &fixed.identity_digest));
    // Fixed program columns are authenticated after the extension prefix,
    // not silently inserted into the base selector/sample offsets.
    try std.testing.expectEqual(legacy.preprocessed_column_count, fixed.preprocessed_column_count);
    var fixed_geometry = try geometry.ForProfile(subject.ProfileV2).init(allocator, &fixed);
    defer fixed_geometry.deinit();
    try geometry.ForProfile(subject.ProfileV2).validateAgainst(&fixed_geometry, &fixed);
    for (fixed.entries) |entry| switch (entry.registry) {
        .infrastructure => |key| switch (key.kind) {
            .program => try std.testing.expectEqual(@as(u32, program.N_FIXED_CONSTRAINTS), entry.constraint_count),
            .poseidon2 => try std.testing.expectEqual(@as(u32, narrow.N_CONSTRAINTS), entry.constraint_count),
            else => {},
        },
        else => {},
    };
    inline for (.{ &legacy, &fixed }) |profile| std.debug.print("C3_PROFILE_RECEIPT tag={d} schema={d} identity={s}\n", .{ @intFromEnum(profile.circuit_profile), profile.schema_version, std.fmt.bytesToHex(profile.identity_digest, .lower) });
    var previous_identity = fixed.identity_digest;
    inline for (.{ @import("stwo_riscv_air_lang").physical_profile.CircuitProfileV1.ethereum_v5, .ethereum_local_zero_v1 }) |selected| {
        var tagged = try subject.deriveAuthorityWithCircuitProfile(allocator, &statement, &manifest, &authenticated, samples, selected);
        defer tagged.deinit();
        try tagged.validateAuthority(allocator, &statement, &manifest, &authenticated);
        try std.testing.expectEqual(subject.CIRCUIT_SCHEMA_VERSION, tagged.schema_version);
        try std.testing.expect(!std.mem.eql(u8, &fixed.identity_digest, &tagged.identity_digest));
        try std.testing.expect(!std.mem.eql(u8, &previous_identity, &tagged.identity_digest));
        std.debug.print("C3_PROFILE_RECEIPT tag={d} schema={d} identity={s}\n", .{ @intFromEnum(tagged.circuit_profile), tagged.schema_version, std.fmt.bytesToHex(tagged.identity_digest, .lower) });
        previous_identity = tagged.identity_digest;
    }
    fixed.circuit_profile = .legacy_v4;
    try std.testing.expectError(error.InvalidStatementShape, fixed.validate());
    fixed.circuit_profile = .fixed_program_narrow_v1;
    fixed.entries[2 * statement.n_components].constraint_count -= 1;
    try std.testing.expectError(error.ProfileMismatch, fixed.validateAuthority(allocator, &statement, &manifest, &authenticated));
}

test "authenticated VM AIR ProfileV2 binds selected physical lookup authority" {
    const allocator = std.testing.allocator;
    var statement = support.retainedSegmentZeroCore();
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &statement,
        &manifest,
    );
    const facts = try subject.testing.expectedFacts(
        allocator,
        &statement,
        &manifest,
    );
    defer allocator.free(facts);

    var profile = try subject.testing.deriveFromFacts(
        allocator,
        &statement,
        &manifest,
        &authenticated,
        facts,
        SAMPLED_VALUE_COUNT,
    );
    defer profile.deinit();
    try profile.validate();

    try std.testing.expectEqual(@as(u32, 372), statement.nInteractionColumns());
    try std.testing.expectEqual(@as(u32, 30), profile.physical_component_count);
    try std.testing.expectEqual(@as(u32, 352), profile.interaction_column_count);
    try std.testing.expectEqual(@as(u32, 88), profile.input_profile.claimed_sum_count);
    try std.testing.expectEqual(
        SAMPLED_VALUE_COUNT,
        profile.input_profile.sampled_value_count,
    );
    try std.testing.expectEqual(
        lookup_physical_v2.STATEMENT_FORMAT_VERSION,
        profile.lookup_statement_format_version,
    );
    try std.testing.expectEqualSlices(
        u8,
        &manifest.identity,
        &profile.lookup_manifest_identity,
    );
    try std.testing.expectEqualSlices(
        u8,
        &authenticated.manifest_identity,
        &profile.lookup_authenticated_manifest_identity,
    );

    const mul = profile.entries[MUL_LOOKUP_INDEX];
    try std.testing.expectEqual(
        subject.AdapterRoleV2.opcode_lookup,
        std.meta.activeTag(mul.registry),
    );
    try std.testing.expectEqual(@as(u32, 11), mul.constraint_count);
    try std.testing.expectEqual(@as(u32, 11), mul.interaction_batch_count);
    try std.testing.expectEqual(@as(u32, 11), mul.claimed_sum_count);
    switch (mul.registry) {
        .opcode_lookup => |key| try std.testing.expectEqual(.mul, key.family),
        else => return error.TestUnexpectedResult,
    }

    var second = try subject.testing.deriveFromFacts(
        allocator,
        &statement,
        &manifest,
        &authenticated,
        facts,
        SAMPLED_VALUE_COUNT,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &profile.identity_digest,
        &second.identity_digest,
    );
}

test "authenticated VM AIR ProfileV2 rejects authority and vtable mutations" {
    const allocator = std.testing.allocator;
    var statement = support.retainedSegmentZeroCore();
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &statement,
        &manifest,
    );
    const facts = try subject.testing.expectedFacts(
        allocator,
        &statement,
        &manifest,
    );
    defer allocator.free(facts);

    facts[MUL_LOOKUP_INDEX].n_constraints += 5;
    try std.testing.expectError(
        error.ConstraintCountMismatch,
        subject.testing.deriveFromFacts(
            allocator,
            &statement,
            &manifest,
            &authenticated,
            facts,
            SAMPLED_VALUE_COUNT,
        ),
    );
    facts[MUL_LOOKUP_INDEX].n_constraints -= 5;

    facts[MUL_LOOKUP_INDEX].max_constraint_log_degree_bound += 1;
    try std.testing.expectError(
        error.ComponentBoundMismatch,
        subject.testing.deriveFromFacts(
            allocator,
            &statement,
            &manifest,
            &authenticated,
            facts,
            SAMPLED_VALUE_COUNT,
        ),
    );
    facts[MUL_LOOKUP_INDEX].max_constraint_log_degree_bound -= 1;

    facts[MUL_LOOKUP_INDEX].composition_log_split += 1;
    try std.testing.expectError(
        error.InconsistentCompositionLogSplit,
        subject.testing.deriveFromFacts(
            allocator,
            &statement,
            &manifest,
            &authenticated,
            facts,
            SAMPLED_VALUE_COUNT,
        ),
    );
    facts[MUL_LOOKUP_INDEX].composition_log_split -= 1;

    var bad_manifest = manifest;
    bad_manifest.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidManifestIdentity,
        subject.testing.deriveFromFacts(
            allocator,
            &statement,
            &bad_manifest,
            &authenticated,
            facts,
            SAMPLED_VALUE_COUNT,
        ),
    );

    var bad_authenticated = authenticated;
    bad_authenticated.activation_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidActivationIdentity,
        subject.testing.deriveFromFacts(
            allocator,
            &statement,
            &manifest,
            &bad_authenticated,
            facts,
            SAMPLED_VALUE_COUNT,
        ),
    );

    var profile = try subject.testing.deriveFromFacts(
        allocator,
        &statement,
        &manifest,
        &authenticated,
        facts,
        SAMPLED_VALUE_COUNT,
    );
    defer profile.deinit();
    profile.entries[MUL_LOOKUP_INDEX].claimed_sum_count += 1;
    try std.testing.expectError(error.InvalidComponentEntry, profile.validate());

    profile.entries[MUL_LOOKUP_INDEX].claimed_sum_count -= 1;
    profile.entries[MUL_LOOKUP_INDEX].interaction.offset += 1;
    try std.testing.expectError(error.InvalidProfileIdentity, profile.validate());
}
