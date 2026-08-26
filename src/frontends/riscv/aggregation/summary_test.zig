const std = @import("std");
const fixture_mod = @import("test_fixture.zig");
const hash = @import("hash.zig");
const manifest = @import("manifest.zig");
const summary_mod = @import("summary.zig");
const types = @import("types.zig");

test "leaf and node summary digest vectors are pinned" {
    var fixture = fixture_mod.twoLeaves(1);
    var storage: [2]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const value = fixture_mod.nonzeroSum();
    const leaf = leafSummary(&session, 0, value.neg());
    const node = try summary_mod.mergePair(
        &session,
        leaf,
        leafSummary(&session, 1, value),
    );
    const leaf_hex = std.fmt.bytesToHex(
        try summary_mod.leafDigest(leaf),
        .lower,
    );
    const node_hex = std.fmt.bytesToHex(
        try summary_mod.nodeDigest(node),
        .lower,
    );
    try std.testing.expectEqualStrings(
        "8501a09f5691d559ae8ebe62989c205ebeb74b833bb2721de5716c947b94b058",
        &leaf_hex,
    );
    try std.testing.expectEqualStrings(
        "4ed538174bff6bb80633e532a6eb10d7db02bf16728790ba9797dad3ca1c699a",
        &node_hex,
    );
}

test "canonical pair and higher merges validate the complete root" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const zero = types.SecureFelt.zero();
    const value = fixture_mod.nonzeroSum();
    const leaves = [4]summary_mod.LeafRelationSummaryV1{
        leafSummary(&session, 0, zero),
        leafSummary(&session, 1, zero),
        leafSummary(&session, 2, value.neg()),
        leafSummary(&session, 3, value),
    };
    const pair0 = try summary_mod.mergePair(&session, leaves[0], leaves[1]);
    const pair1 = try summary_mod.mergePair(&session, leaves[2], leaves[3]);
    const root = try summary_mod.mergeClosedSubtrees(&session, pair0, pair1);
    try summary_mod.validateRoot(&session, root, rootIdentity(&session));
    try std.testing.expectEqual(@as(u32, 0), root.first_leaf);
    try std.testing.expectEqual(@as(u32, 4), root.leaf_count);
    try std.testing.expectEqual(@as(u8, 2), root.height);
    try std.testing.expect(root.closed);
    try std.testing.expect(root.residual_guest_sum.isZero());
}

test "one-pair tree is a complete root" {
    var fixture = fixture_mod.twoLeaves(1);
    var storage: [2]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const value = fixture_mod.nonzeroSum();
    const root = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 0, value.neg()),
        leafSummary(&session, 1, value),
    );
    try summary_mod.validateRoot(&session, root, rootIdentity(&session));
    try std.testing.expectEqual(@as(u8, 1), root.height);
}

test "leaf and node encoders are the exact digest preimages" {
    var fixture = fixture_mod.twoLeaves(1);
    var storage: [2]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const value = fixture_mod.nonzeroSum();
    const leaf = leafSummary(&session, 0, value.neg());
    const node = try summary_mod.mergePair(
        &session,
        leaf,
        leafSummary(&session, 1, value),
    );

    var leaf_bytes: [summary_mod.LEAF_SUMMARY_ENCODED_LEN]u8 = undefined;
    try std.testing.expectEqual(
        leaf_bytes.len,
        try summary_mod.encodeLeafSummary(leaf, &leaf_bytes),
    );
    try std.testing.expect(hash.eql(
        hash.hashDomain(hash.LEAF_SUMMARY_DOMAIN, &leaf_bytes),
        try summary_mod.leafDigest(leaf),
    ));

    var node_bytes: [summary_mod.NODE_SUMMARY_ENCODED_LEN]u8 = undefined;
    try std.testing.expectEqual(
        node_bytes.len,
        try summary_mod.encodeNodeSummary(node, &node_bytes),
    );
    try std.testing.expect(hash.eql(
        hash.hashDomain(hash.NODE_SUMMARY_DOMAIN, &node_bytes),
        try summary_mod.nodeDigest(node),
    ));
    var short: [summary_mod.LEAF_SUMMARY_ENCODED_LEN - 1]u8 = undefined;
    try std.testing.expectError(
        error.IncorrectBufferLength,
        summary_mod.encodeLeafSummary(leaf, &short),
    );
}

test "leaf structure rejects cross-session challenge role count and call mutations" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const valid = leafSummary(&session, 2, fixture_mod.nonzeroSum().neg());

    {
        var other_fixture = fixture_mod.fourLeaves();
        other_fixture.descriptors[0].main_root[0] ^= 1;
        var other_storage: [4]manifest.PreparedLeafV1 = undefined;
        const other_session = try manifest.prepare(
            other_fixture.view(),
            other_fixture.accepted,
            &other_storage,
        );
        try std.testing.expectError(
            error.SessionMismatch,
            summary_mod.validateLeafStructure(&other_session, valid),
        );
    }
    {
        var mutated = valid;
        mutated.challenge_context_digest[0] ^= 1;
        try std.testing.expectError(
            error.ChallengeContextMismatch,
            summary_mod.validateLeafStructure(&session, mutated),
        );
    }
    {
        var mutated = valid;
        mutated.leaf_role = .poseidon2_provider;
        try std.testing.expectError(
            error.LeafRoleMismatch,
            summary_mod.validateLeafStructure(&session, mutated),
        );
    }
    {
        var mutated = valid;
        mutated.guest_call_count = 2;
        mutated.request_count = 2;
        try std.testing.expectError(
            error.CallCountMismatch,
            summary_mod.validateLeafStructure(&session, mutated),
        );
    }
    {
        var mutated = valid;
        mutated.request_count = 0;
        mutated.supply_count = 1;
        try std.testing.expectError(
            error.DerivedCountMismatch,
            summary_mod.validateLeafStructure(&session, mutated),
        );
    }
    {
        var mutated = valid;
        mutated.guest_call_commitment[0] ^= 1;
        try std.testing.expectError(
            error.CallCommitmentMismatch,
            summary_mod.validateLeafStructure(&session, mutated),
        );
    }
    {
        var mutated = valid;
        mutated.leaf_statement_digest[0] ^= 1;
        try std.testing.expectError(
            error.LeafStatementMismatch,
            summary_mod.validateLeafStructure(&session, mutated),
        );
    }
}

test "empty and noncanonical relation summaries reject" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    {
        const invalid = leafSummary(&session, 0, fixture_mod.nonzeroSum());
        try std.testing.expectError(
            error.NonZeroEmptyRelationSum,
            summary_mod.validateLeafStructure(&session, invalid),
        );
    }
    {
        var invalid = leafSummary(&session, 2, fixture_mod.nonzeroSum());
        invalid.signed_guest_sum.limbs[3] = types.M31_MODULUS;
        try std.testing.expectError(
            error.NonCanonicalM31,
            summary_mod.validateLeafStructure(&session, invalid),
        );
        var bytes: [summary_mod.LEAF_SUMMARY_ENCODED_LEN]u8 = undefined;
        try std.testing.expectError(
            error.NonCanonicalM31,
            summary_mod.encodeLeafSummary(invalid, &bytes),
        );
    }
}

test "pair merge rejects swapped and non-closing siblings" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const value = fixture_mod.nonzeroSum();
    const core = leafSummary(&session, 2, value.neg());
    const provider = leafSummary(&session, 3, value);
    try std.testing.expectError(
        error.NonCanonicalPair,
        summary_mod.mergePair(&session, provider, core),
    );

    var non_closing = provider;
    non_closing.signed_guest_sum = .{ .limbs = .{ 5, 6, 7, 8 } };
    try std.testing.expectError(
        error.PairRelationNotClosed,
        summary_mod.mergePair(&session, core, non_closing),
    );
}

test "higher merge rejects swaps duplicates omissions and context mutation" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const zero = types.SecureFelt.zero();
    const value = fixture_mod.nonzeroSum();
    const pair0 = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 0, zero),
        leafSummary(&session, 1, zero),
    );
    const pair1 = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 2, value.neg()),
        leafSummary(&session, 3, value),
    );
    try std.testing.expectError(
        error.NonAdjacentSubtrees,
        summary_mod.mergeClosedSubtrees(&session, pair1, pair0),
    );
    try std.testing.expectError(
        error.NonAdjacentSubtrees,
        summary_mod.mergeClosedSubtrees(&session, pair0, pair0),
    );
    try std.testing.expectError(
        error.IncompleteRootRange,
        summary_mod.validateRoot(&session, pair0, rootIdentity(&session)),
    );

    var cross_challenge = pair1;
    cross_challenge.challenge_context_digest[0] ^= 1;
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        summary_mod.mergeClosedSubtrees(&session, pair0, cross_challenge),
    );
    var cross_session = pair1;
    cross_session.session_digest[0] ^= 1;
    try std.testing.expectError(
        error.SessionMismatch,
        summary_mod.mergeClosedSubtrees(&session, pair0, cross_session),
    );
}

test "higher merge uses checked aggregate counts" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const zero = types.SecureFelt.zero();
    var left = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 0, zero),
        leafSummary(&session, 1, zero),
    );
    const value = fixture_mod.nonzeroSum();
    var right = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 2, value.neg()),
        leafSummary(&session, 3, value),
    );
    const enormous = std.math.maxInt(u64) - 1;
    left.request_count = enormous;
    left.supply_count = enormous;
    right.request_count = enormous;
    right.supply_count = enormous;
    var synthetic_session = session;
    synthetic_session.total_request_count = std.math.maxInt(u64);
    synthetic_session.total_supply_count = std.math.maxInt(u64);
    try std.testing.expectError(
        error.AggregateCountOverflow,
        summary_mod.mergeClosedSubtrees(&synthetic_session, left, right),
    );
}

test "root rejects count call request and advertised identity mutations" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const zero = types.SecureFelt.zero();
    const value = fixture_mod.nonzeroSum();
    const left = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 0, zero),
        leafSummary(&session, 1, zero),
    );
    const right = try summary_mod.mergePair(
        &session,
        leafSummary(&session, 2, value.neg()),
        leafSummary(&session, 3, value),
    );
    const root = try summary_mod.mergeClosedSubtrees(&session, left, right);

    {
        var mutated = root;
        mutated.request_count = 0;
        mutated.supply_count = 0;
        try std.testing.expectError(
            error.RootCountMismatch,
            summary_mod.validateRoot(&session, mutated, rootIdentity(&session)),
        );
    }
    {
        var mutated = root;
        mutated.call_subtree_digest[0] ^= 1;
        try std.testing.expectError(
            error.RootCallIdentityMismatch,
            summary_mod.validateRoot(&session, mutated, rootIdentity(&session)),
        );
    }
    {
        var mutated = root;
        mutated.request_subtree_digest[0] ^= 1;
        try std.testing.expectError(
            error.RootRequestIdentityMismatch,
            summary_mod.validateRoot(&session, mutated, rootIdentity(&session)),
        );
    }
    {
        var advertised = rootIdentity(&session);
        advertised.statement_root[0] ^= 1;
        try std.testing.expectError(
            error.RootAdvertisedIdentityMismatch,
            summary_mod.validateRoot(&session, root, advertised),
        );
    }
}

fn leafSummary(
    session: *const manifest.PreparedSessionV1,
    index: u32,
    signed_sum: types.SecureFelt,
) summary_mod.LeafRelationSummaryV1 {
    const descriptor = session.leaf(index) catch unreachable;
    const is_request = descriptor.descriptor.role == .core_request;
    return .{
        .session_digest = session.session_digest,
        .challenge_context_digest = session.challenge.challenge_context_digest,
        .leaf_index = index,
        .leaf_role = descriptor.descriptor.role,
        .leaf_statement_digest = descriptor.descriptor.leaf_statement_digest,
        .guest_call_commitment = descriptor.descriptor.guest_call_commitment,
        .guest_call_count = descriptor.descriptor.guest_call_count,
        .request_count = if (is_request)
            descriptor.descriptor.guest_call_count
        else
            0,
        .supply_count = if (is_request)
            0
        else
            descriptor.descriptor.guest_call_count,
        .signed_guest_sum = signed_sum,
    };
}

fn rootIdentity(
    session: *const manifest.PreparedSessionV1,
) summary_mod.RootIdentityV1 {
    return .{
        .statement_root = session.statement_root,
        .artifact_root = session.artifact_root,
    };
}
