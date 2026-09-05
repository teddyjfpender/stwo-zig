const std = @import("std");

const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const support = @import("ethereum_leaf_context_v1_test_support.zig");
const subject = @import("vm_air_profile_v2.zig");

const SAMPLED_VALUE_COUNT: u32 = 317;
const MUL_LOOKUP_INDEX: usize = 19;

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
