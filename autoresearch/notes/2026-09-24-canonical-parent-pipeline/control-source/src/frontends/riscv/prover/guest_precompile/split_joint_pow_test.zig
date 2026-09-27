const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const challenge = @import("../../aggregation/challenge.zig");
const fixture_mod = @import("../../aggregation/test_fixture.zig");
const hash = @import("../../aggregation/hash.zig");
const manifest = @import("../../aggregation/manifest.zig");
const joint_pow = @import("split_joint_pow.zig");

test "R-008 joint PoW is manifest-bound and precedes shared relations" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const prepared = try joint_pow.prepare(&session);
    const verified = try joint_pow.verify(&session, prepared);

    try std.testing.expect(joint_pow.RESEARCH_ONLY);
    try std.testing.expect(!joint_pow.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(!joint_pow.CHANGES_MANIFEST_V1);
    try std.testing.expect(joint_pow.JOINT_POW_PRECEDES_SHARED_RELATION);
    try std.testing.expect(!joint_pow.LEAF_BINDING_IS_IN_PRODUCTION_TRANSCRIPT);
    try std.testing.expectEqual(
        joint_pow.JOINT_POW_BITS,
        @import("../../air/transcript/mod.zig").INTERACTION_POW_BITS,
    );
    try std.testing.expect(hash.eql(
        prepared.pow_context_digest,
        verified.session_digest,
    ));
    try std.testing.expect(!hash.eql(
        session.challenge.challenge_context_digest,
        prepared.relation_context.challenge_context_digest,
    ));
    try std.testing.expect(!@import("../../aggregation/types.zig").SecureFelt.eql(
        session.challenge.z,
        prepared.relation_context.z,
    ));
    try std.testing.expect(!hash.eql(
        challenge.derive(session.session_digest).challenge_context_digest,
        prepared.relation_context.challenge_context_digest,
    ));
}

test "R-008 joint PoW and role-local transcript vectors are pinned" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const prepared = try joint_pow.prepare(&session);

    var caller = Blake2sChannel{};
    try joint_pow.mixLeafBinding(
        &caller,
        &session,
        prepared,
        0,
        .core_request,
    );
    var provider = Blake2sChannel{};
    try joint_pow.mixLeafBinding(
        &provider,
        &session,
        prepared,
        1,
        .poseidon2_provider,
    );

    const pow_context_hex = std.fmt.bytesToHex(
        prepared.pow_context_digest,
        .lower,
    );
    const relation_context_hex = std.fmt.bytesToHex(
        prepared.relation_context.challenge_context_digest,
        .lower,
    );
    const caller_hex = std.fmt.bytesToHex(caller.digestBytes(), .lower);
    const provider_hex = std.fmt.bytesToHex(provider.digestBytes(), .lower);

    try std.testing.expectEqual(@as(u64, 2856), prepared.interaction_pow);
    try std.testing.expectEqualStrings(
        "eaec0b366e755619b273c36884b0a53de1a88ea1e8821055854b8de0d79a56cd",
        &pow_context_hex,
    );
    try std.testing.expectEqualStrings(
        "24100831b3c07dc6e18c37123849f11cce821f324106915e5654e2262cdc053b",
        &relation_context_hex,
    );
    try std.testing.expectEqualStrings(
        "d6550b0783f99eb3b6c525f356895340c69527eb1c8f6c9eb8c1f1a12e93bf2e",
        &caller_hex,
    );
    try std.testing.expectEqualStrings(
        "55d2c98ac06b25a895136f419f3a79c6f65d7ebd6436af1e323f1f1169658f96",
        &provider_hex,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &caller.digestBytes(),
        &provider.digestBytes(),
    ));
}

test "R-008 joint PoW rejects every authority mutation" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    var session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const prepared = try joint_pow.prepare(&session);

    var wrong_nonce = prepared;
    wrong_nonce.interaction_pow +%= 1;
    while (powIsValid(&session, wrong_nonce.interaction_pow))
        wrong_nonce.interaction_pow +%= 1;
    try std.testing.expectError(
        error.InvalidJointProofOfWork,
        joint_pow.verify(&session, wrong_nonce),
    );

    var wrong_pow_context = prepared;
    wrong_pow_context.pow_context_digest[0] ^= 1;
    try std.testing.expectError(
        error.PowContextMismatch,
        joint_pow.verify(&session, wrong_pow_context),
    );

    var wrong_relation = prepared;
    wrong_relation.relation_context.z.limbs[0] +%= 1;
    try std.testing.expectError(
        error.RelationContextMismatch,
        joint_pow.verify(&session, wrong_relation),
    );

    var wrong_relation_seed = prepared;
    wrong_relation_seed.relation_context.session_digest[0] ^= 1;
    try std.testing.expectError(
        error.RelationContextMismatch,
        joint_pow.verify(&session, wrong_relation_seed),
    );

    var pre_pow_relation = prepared;
    pre_pow_relation.relation_context = session.challenge;
    try std.testing.expectError(
        error.RelationContextMismatch,
        joint_pow.verify(&session, pre_pow_relation),
    );

    var other_fixture = fixture_mod.twoLeaves(1);
    var other_storage: [2]manifest.PreparedLeafV1 = undefined;
    const other_session = try manifest.prepare(
        other_fixture.view(),
        other_fixture.accepted,
        &other_storage,
    );
    try std.testing.expectError(
        error.SessionMismatch,
        joint_pow.verify(&other_session, prepared),
    );

    storage[0].descriptor.main_root[0] ^= 1;
    try std.testing.expectError(
        error.PreparedSessionMutated,
        joint_pow.verify(&session, prepared),
    );
    storage[0].descriptor.main_root[0] ^= 1;

    session.challenge.alpha.limbs[0] +%= 1;
    try std.testing.expectError(
        error.PreparedSessionMutated,
        joint_pow.verify(&session, prepared),
    );
}

test "R-008 leaf binding rejects role and challenge changes atomically" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const prepared = try joint_pow.prepare(&session);

    var channel = Blake2sChannel{};
    channel.mixU32s(&.{0x1234_5678});
    const before_digest = channel.digestBytes();
    const before_draws = channel.n_draws;
    try std.testing.expectError(
        error.LeafRoleMismatch,
        joint_pow.mixLeafBinding(
            &channel,
            &session,
            prepared,
            0,
            .poseidon2_provider,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before_digest,
        &channel.digestBytes(),
    );
    try std.testing.expectEqual(before_draws, channel.n_draws);

    var wrong = prepared;
    wrong.relation_context.alpha.limbs[0] +%= 1;
    try std.testing.expectError(
        error.RelationContextMismatch,
        joint_pow.mixLeafBinding(
            &channel,
            &session,
            wrong,
            0,
            .core_request,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before_digest,
        &channel.digestBytes(),
    );
    try std.testing.expectEqual(before_draws, channel.n_draws);

    try std.testing.expectError(
        error.LeafIndexOutOfRange,
        joint_pow.mixLeafBinding(
            &channel,
            &session,
            prepared,
            9,
            .core_request,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before_digest,
        &channel.digestBytes(),
    );
}

fn powIsValid(
    session: *const manifest.PreparedSessionV1,
    nonce: u64,
) bool {
    var channel = Blake2sChannel{};
    channel.mixU32s(&joint_pow.joint_pow_domain_words);
    var words: [8]u32 = undefined;
    inline for (0..words.len) |index| {
        const offset = index * 4;
        words[index] = std.mem.readInt(
            u32,
            session.session_digest[offset..][0..4],
            .little,
        );
    }
    channel.mixU32s(&words);
    return channel.verifyPowNonce(joint_pow.JOINT_POW_BITS, nonce);
}
