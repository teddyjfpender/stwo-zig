const std = @import("std");
const challenge = @import("challenge.zig");
const fixture_mod = @import("test_fixture.zig");
const hash = @import("hash.zig");
const manifest = @import("manifest.zig");
const tree = @import("tree.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const production_blake2s = @import("stwo_core").channel.blake2s;

test "empty one-call two-pair and maximum-count manifest vectors are pinned" {
    var four = fixture_mod.fourLeaves();
    var four_storage: [4]manifest.PreparedLeafV1 = undefined;
    const four_session = try manifest.prepare(
        four.view(),
        four.accepted,
        &four_storage,
    );
    var maximum = fixture_mod.twoLeaves((types.M31_MODULUS - 1) / 2);
    var maximum_storage: [2]manifest.PreparedLeafV1 = undefined;
    const maximum_session = try manifest.prepare(
        maximum.view(),
        maximum.accepted,
        &maximum_storage,
    );
    const four_session_hex = std.fmt.bytesToHex(
        four_session.session_digest,
        .lower,
    );
    const four_challenge_hex = std.fmt.bytesToHex(
        four_session.challenge.challenge_context_digest,
        .lower,
    );
    const maximum_session_hex = std.fmt.bytesToHex(
        maximum_session.session_digest,
        .lower,
    );
    const maximum_challenge_hex = std.fmt.bytesToHex(
        maximum_session.challenge.challenge_context_digest,
        .lower,
    );
    try std.testing.expectEqualStrings(
        "cadd281a567fb13488f610c59ab69696cba40c756349223882ab96668961d49d",
        &four_session_hex,
    );
    try std.testing.expectEqualStrings(
        "f22b7f5bf0c08cbd4b6f216bc4cf190eb61d46377c0bc8a6279ee03e746f5398",
        &four_challenge_hex,
    );
    try std.testing.expectEqualStrings(
        "51a73bbf3b10ae54c3ac3244fe2cdd514d75aa95b0bcfeedb4cfb42970f7d736",
        &maximum_session_hex,
    );
    try std.testing.expectEqualStrings(
        "bb99b9dd043320205ea805d5b7bb9e2fb4b9aff9caa6457e7024be7f7fdcd31b",
        &maximum_challenge_hex,
    );
}

test "two-pair manifest prepares and canonical bytes hash the session" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );

    try std.testing.expectEqual(@as(u8, 2), session.tree_height);
    try std.testing.expectEqual(@as(u64, 1), session.total_request_count);
    try std.testing.expectEqual(@as(u64, 1), session.total_supply_count);
    try std.testing.expectEqual(@as(u64, 2), session.total_leaf_call_count);
    try std.testing.expect(hash.eql(session.request_root, fixture.header.request_set_digest));
    try session.challenge.validate();

    const encoded_len = wire.HEADER_ENCODED_LEN +
        4 * wire.DESCRIPTOR_ENCODED_LEN;
    var encoded: [encoded_len]u8 = undefined;
    try std.testing.expectEqual(
        encoded.len,
        try session.encodeCanonical(&encoded),
    );
    var independent = hash.Blake2s256.init(.{});
    independent.update(hash.SESSION_DOMAIN);
    independent.update(&encoded);
    var independent_digest: hash.Digest = undefined;
    independent.final(&independent_digest);
    try std.testing.expect(hash.eql(independent_digest, session.session_digest));

    try std.testing.expectEqualSlices(u8, &types.MANIFEST_MAGIC, encoded[0..8]);
    try std.testing.expectEqual(
        types.FORMAT_VERSION,
        std.mem.readInt(u16, encoded[8..10], .little),
    );
    const profile_begin = 12;
    const profile_end = profile_begin + types.AGGREGATION_PROFILE_TAG.len;
    try std.testing.expectEqualSlices(
        u8,
        types.AGGREGATION_PROFILE_TAG,
        encoded[profile_begin..profile_end],
    );
}

test "shared challenge matches production secure-felt rejection schedule" {
    var fixture = fixture_mod.fourLeaves();
    var storage: [4]manifest.PreparedLeafV1 = undefined;
    const session = try manifest.prepare(
        fixture.view(),
        fixture.accepted,
        &storage,
    );
    const reference = challenge.drawTwoSecureFelts(
        session.challenge.challenge_context_digest,
    );

    var channel = production_blake2s.Blake2sChannel{};
    channel.updateDigest(session.challenge.challenge_context_digest);
    const production = try channel.drawSecureFelts(std.testing.allocator, 2);
    defer std.testing.allocator.free(production);
    for (production, reference) |production_felt, reference_felt| {
        const limbs = production_felt.toM31Array();
        for (limbs, reference_felt.limbs) |production_limb, reference_limb| {
            try std.testing.expectEqual(reference_limb, production_limb.v);
        }
    }
    try std.testing.expect(types.SecureFelt.eql(reference[0], session.challenge.z));
    try std.testing.expect(types.SecureFelt.eql(reference[1], session.challenge.alpha));

    var mutated = session.challenge;
    mutated.alpha.limbs[0] +%= 1;
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        mutated.validate(),
    );
}

test "manifest rejects role swaps omissions duplicate and unordered jobs" {
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[0].role = .poseidon2_provider;
        fixture.descriptors[1].role = .core_request;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.LeafRoleMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        const omitted = types.ManifestViewV1{
            .header = fixture.header,
            .descriptors = fixture.descriptors[0..3],
        };
        var storage: [3]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.DescriptorCountMismatch,
            manifest.prepare(omitted, fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[2].job_digest = fixture.descriptors[0].job_digest;
        fixture.descriptors[3].job_digest = fixture.descriptors[0].job_digest;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.JobDigestsNotStrictlyIncreasing,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[2].job_digest = fixture_mod.digest(0x08);
        fixture.descriptors[3].job_digest = fixture_mod.digest(0x08);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.JobDigestsNotStrictlyIncreasing,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
}

test "manifest rejects call and count divergence" {
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[3].guest_call_count = 2;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.PairCallCountMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[3].guest_call_commitment = fixture_mod.digest(0x39);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.PairCallCommitmentMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[0].guest_call_commitment = fixture_mod.digest(0x39);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.NonCanonicalEmptyCallCommitment,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[2].guest_call_commitment = hash.emptyCallCommitment();
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.EmptyCommitmentForNonEmptyCalls,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
}

test "zero-row component presence and protocol identities fail closed" {
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[0].flags = 0;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.GuestComponentMissingOrUnknownFlags,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.proof_protocol_digest = fixture_mod.digest(0xb1);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.ProtocolIdentityMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[2].relation_registry_digest = fixture_mod.digest(0xb2);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.ProtocolIdentityMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[2].execution_semantic_digest = fixture_mod.digest(0xb3);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.ExecutionProfileMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
}

test "fixed header tags schema bounds and reserved bytes fail closed" {
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.magic[0] ^= 1;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.InvalidManifestMagic,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.version += 1;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.UnsupportedFormatVersion,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.aggregation_profile_id += 1;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.AggregationProfileMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.relation_schema_id += 1;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.RelationSchemaMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.reserved[6] = 1;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.NonZeroReservedBits,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.leaf_count = 3;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.InvalidLeafCount,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
}

test "descriptor position reserved and digest fields fail closed" {
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[2].pair_index = 0;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.NonCanonicalLeafPosition,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[0].reserved_tail = 1;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.NonZeroReservedBits,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.descriptors[1].main_root = .{0} ** 32;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.ZeroDescriptorDigest,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.accepted.proof_protocol_digest = .{0} ** 32;
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.ZeroProtocolIdentity,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
}

test "digest frontier covers the admitted maximum without heap storage" {
    try std.testing.expect(types.validLeafCount(types.MAX_LEAVES));
    try std.testing.expect(!types.validLeafCount(types.MAX_LEAVES + 1));
    try std.testing.expect(!types.validLeafCount(3));

    var frontier = tree.DigestFrontier.init(hash.STATEMENT_NODE_DOMAIN);
    for (0..types.MAX_LEAVES) |index| {
        var leaf = fixture_mod.digest(0xd0);
        std.mem.writeInt(u64, leaf[0..8], index, .little);
        try frontier.push(hash.hashDomain(hash.STATEMENT_LEAF_DOMAIN, &leaf));
    }
    const root = try frontier.finish();
    try std.testing.expect(!hash.isZero(root));
    try std.testing.expectError(
        error.TooManyLeaves,
        frontier.push(fixture_mod.digest(0xd1)),
    );
}

test "checked call bound accepts the boundary and rejects its successor" {
    const max_call_count: u64 = (types.M31_MODULUS - 1) / 2;
    {
        var fixture = fixture_mod.twoLeaves(max_call_count);
        var storage: [2]manifest.PreparedLeafV1 = undefined;
        const session = try manifest.prepare(
            fixture.view(),
            fixture.accepted,
            &storage,
        );
        try std.testing.expectEqual(max_call_count, session.total_request_count);
        try std.testing.expectEqual(2 * max_call_count, session.total_leaf_call_count);
    }
    {
        var fixture = fixture_mod.twoLeaves(max_call_count + 1);
        var storage: [2]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.CallCountOutOfRange,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
}

test "request root storage and canonical output are exact" {
    {
        var fixture = fixture_mod.fourLeaves();
        fixture.header.request_set_digest = fixture_mod.digest(0xc1);
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.RequestSetDigestMismatch,
            manifest.prepare(fixture.view(), fixture.accepted, &storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        var short_storage: [3]manifest.PreparedLeafV1 = undefined;
        try std.testing.expectError(
            error.IncorrectStorageLength,
            manifest.prepare(fixture.view(), fixture.accepted, &short_storage),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        const session = try manifest.prepare(
            fixture.view(),
            fixture.accepted,
            &storage,
        );
        const encoded_len = wire.HEADER_ENCODED_LEN +
            4 * wire.DESCRIPTOR_ENCODED_LEN;
        var short: [encoded_len - 1]u8 = undefined;
        try std.testing.expectError(
            error.IncorrectBufferLength,
            session.encodeCanonical(&short),
        );
    }
    {
        var fixture = fixture_mod.fourLeaves();
        var storage: [4]manifest.PreparedLeafV1 = undefined;
        const session = try manifest.prepare(
            fixture.view(),
            fixture.accepted,
            &storage,
        );
        storage[0].descriptor.main_root[0] ^= 1;
        const encoded_len = wire.HEADER_ENCODED_LEN +
            4 * wire.DESCRIPTOR_ENCODED_LEN;
        var encoded: [encoded_len]u8 = undefined;
        try std.testing.expectError(
            error.PreparedSessionMutated,
            session.encodeCanonical(&encoded),
        );
    }
}
