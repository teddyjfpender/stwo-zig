const std = @import("std");

const node_profile = @import("recursive_temporal_node_profile_v1.zig");
const plan_mod = @import("recursive_temporal_statement_plan_v1.zig");
const subject = @import("recursive_temporal_profile_plan_transport_v1.zig");

test "profile transport projects all nine ordered authorities without native limbs" {
    const plan = try fixturePlan();
    const projected = try subject.ProfilePlanTransportV1.init(&plan);
    try projected.validateAgainst(&plan);
    try std.testing.expectEqual(@as(usize, 9), projected.entries.len);
    try std.testing.expectEqual(subject.EntryKindV1.real_h1, projected.entries[0].kind);
    try std.testing.expectEqual(subject.EntryKindV1.empty_h1, projected.entries[1].kind);
    for (projected.entries[2..], 2..) |entry, height| {
        try std.testing.expectEqual(subject.EntryKindV1.upper, entry.kind);
        try std.testing.expectEqual(@as(u8, @intCast(height)), entry.parent_height);
    }
    try std.testing.expectEqualDeep(
        projected.entries[0].next_parent_vk_sha256,
        projected.entries[2].verification_key_sha256,
    );

    const encoded = try subject.encodeCanonicalJson(std.testing.allocator, &projected);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(encoded.len > 1 and encoded[encoded.len - 1] == '\n');
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"schema\":\"stwo.recursion.temporal-profile-plan.v2\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "verification_key_id",
    ) == null);
}

test "profile transport rejects mutation and wrong source plan" {
    const plan = try fixturePlan();
    var projected = try subject.ProfilePlanTransportV1.init(&plan);
    projected.entries[4].child_composition_manifest_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProfilePlanTransport,
        projected.validate(),
    );

    projected = try subject.ProfilePlanTransportV1.init(&plan);
    projected.entries[4].parent_outer_manifest_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProfilePlanTransport,
        projected.validate(),
    );

    projected = try subject.ProfilePlanTransportV1.init(&plan);
    var other = plan;
    other.real_h1 = try node_profile.NodeProfileV1.init(
        .real_parent_h1,
        1,
        plan.real_h1.verification_key_id,
        plan.real_h1.next_parent_vk_id,
        sha(99),
        plan.real_h1.air_program_id,
        plan.real_h1.profile_id,
        .recursiveParentFunctional(),
        .recursiveParentFunctional(),
        .temporalParentV3(),
    );
    try std.testing.expectError(
        error.ProfilePlanTransportMismatch,
        projected.validateAgainst(&other),
    );
}

fn fixturePlan() !plan_mod.ProfilePlanV1 {
    var upper: [plan_mod.UPPER_PROFILE_COUNT]node_profile.NodeProfileV1 = undefined;
    for (&upper, 0..) |*entry, index| {
        const height: u8 = @intCast(index + 2);
        entry.* = try profile(
            .recursive_parent,
            height,
            digest(10 + index),
            digest(11 + index),
            .recursiveParentFunctional(),
            .recursiveParentFunctional(),
            .recursiveNodeV1(),
        );
    }
    const child_vk = upper[0].verification_key_id;
    return .{
        .real_h1 = try profile(
            .real_parent_h1,
            1,
            digest(101),
            child_vk,
            .segmentV2Poseidon2(),
            .recursiveParentFunctional(),
            .temporalParentV3(),
        ),
        .empty_h1 = try profile(
            .empty_parent_h1,
            1,
            digest(201),
            child_vk,
            .prooflessEmpty(),
            .recursiveParentFunctional(),
            .emptyParentV1(),
        ),
        .upper = upper,
    };
}

fn profile(
    kind: node_profile.KindV1,
    height: u8,
    verification_key: [8]u32,
    next_key: [8]u32,
    admitted: @import("recursive_temporal_proof_security_v1.zig").ProofSecurityV1,
    parent: @import("recursive_temporal_proof_security_v1.zig").ProofSecurityV1,
    transcript: @import("recursive_temporal_child_transcript_authority_v1.zig").DescriptorV1,
) !node_profile.NodeProfileV1 {
    return node_profile.NodeProfileV1.init(
        kind,
        height,
        verification_key,
        next_key,
        sha(31 + height),
        digest(301 + @as(usize, height)),
        digest(401 + @as(usize, height)),
        admitted,
        parent,
        transcript,
    );
}

fn digest(seed: usize) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = @intCast(seed + index + 1);
    return result;
}

fn sha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
