const std = @import("std");
const stwo_core = @import("stwo_core");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");

const m31 = stwo_core.fields.m31;
const Digest = pair_node.Digest;

const GOLDEN_WIRE_SHA256 = hexDigest(
    "548dfc7e9d531f424c2ee2c22f7c50ef9c0c2192b33b8a1c9c60d92f7910916c",
);
const GOLDEN_RECORD_ID = Digest{
    2_039_660_602, 115_237_135,   1_331_741_423, 1_294_625_639,
    1_449_265_885, 1_690_024_629, 188_314_213,   1_988_757_495,
};
const GOLDEN_STATEMENT_ID = Digest{
    1_668_581_139, 1_656_416_802, 50_065_182,  2_125_230_098,
    410_337_995,   170_031_781,   255_905_502, 1_004_825_127,
};
const GOLDEN_PROOF_ID = Digest{
    2_090_435_214, 1_960_971_288, 245_807_019, 1_845_949_681,
    885_842_594,   425_023_899,   425_575_428, 2_080_706_910,
};
const GOLDEN_TRANSCRIPT_ID = Digest{
    2_060_483_450, 924_184_605,   949_267_678, 1_412_135_031,
    323_620_981,   1_611_917_707, 215_859_777, 1_824_587_802,
};
const GOLDEN_SUMMARY_ID = Digest{
    992_521_607,   547_623_542, 743_238_183,   1_184_546_926,
    1_925_167_659, 358_932_843, 1_946_952_417, 716_933_793,
};
const GOLDEN_NODE_ID = Digest{
    1_121_897_635, 1_933_104_947, 1_194_423_304, 1_229_304_646,
    314_473_721,   245_804_358,   601_591_189,   264_131_684,
};

const test_support = @import("pair_node_test_support.zig");
const Fixture = test_support.Fixture;
const makeChild = test_support.makeChild;
const verifiedChild = test_support.verifiedChild;
const id = test_support.id;
const hexDigest = test_support.hexDigest;

test "R-009 pair node format seal is independently derivable" {
    const derived = pair_node.formatId();
    try std.testing.expectEqual(pair_node.FORMAT_ID_WORDS, derived);
}

test "R-009 pair node pins the exact successful permutation call tree" {
    const expected_stages = [_]pair_node.AuthenticationPermutationStageV1{
        .format_id,
        .protocol_id,
        .relation_name_id,
        .relation_domain_id,
        .poseidon_parameter_id,
        .empty_call_commitment,
        .challenge_context_id,
        .authority_context_id,
        .statement_fold,
        .proof_fold,
        .transcript_fold,
        .summary_fold,
        .node_id,
    };
    const expected_permutations = [_]usize{
        7, 6, 3, 2, 21, 3, 4, 10, 7, 7, 7, 9, 8,
    };
    try std.testing.expectEqual(
        expected_stages.len,
        pair_node.AUTHENTICATION_PERMUTATION_CALL_TREE_V1.len,
    );
    for (
        pair_node.AUTHENTICATION_PERMUTATION_CALL_TREE_V1,
        expected_stages,
        expected_permutations,
    ) |call, expected_stage, expected_count| {
        try std.testing.expectEqual(expected_stage, call.stage);
        try std.testing.expectEqual(@as(usize, 1), call.invocations);
        try std.testing.expectEqual(expected_count, call.total());
        const independently_derived = switch (call.encoding) {
            .canonical_words => channel.canonicalWordPermutationCount(
                call.unit_count,
            ),
            .injective_bytes => channel.bytePermutationCount(call.unit_count),
        };
        try std.testing.expectEqual(
            independently_derived,
            call.permutations_per_invocation,
        );
    }
    try std.testing.expectEqual(
        @as(usize, 39),
        pair_node.authenticationPermutationTotal(.suite_preparation),
    );
    try std.testing.expectEqual(
        @as(usize, 17),
        pair_node.authenticationPermutationTotal(.context_preparation),
    );
    try std.testing.expectEqual(
        @as(usize, 38),
        pair_node.authenticationPermutationTotal(.authenticated_output),
    );
    try std.testing.expectEqual(
        @as(usize, 229),
        pair_node.AuthenticationPermutationBaselineV1.historical_audit_static_estimate,
    );
    try std.testing.expectEqual(
        @as(usize, 55),
        pair_node.AuthenticationPermutationBaselineV1.pre_context_cache_prepared_root,
    );
    try std.testing.expectEqual(
        @as(usize, 94),
        pair_node.AuthenticationPermutationBaselineV1.pre_context_cache_convenience_root,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        pair_node.AuthenticationAllocationCostV1.suite_preparation,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        pair_node.AuthenticationAllocationCostV1.context_preparation,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        pair_node.AuthenticationAllocationCostV1.successful_context_prepared_root,
    );
}

test "R-009 pair node fixes format encoding and authenticated identities" {
    const fixture = try Fixture.init();
    try fixture.authority.validate();
    try fixture.record.validate();

    var encoded: [pair_node.ENCODED_LEN]u8 = undefined;
    try pair_node.encodeInto(&fixture.record, &encoded);
    var decoded: pair_node.PairNodeRecordV1 = undefined;
    try pair_node.decodeInto(&decoded, &encoded);
    try std.testing.expectEqualDeep(fixture.record, decoded);

    const pair = try pair_node.authenticatePair(&fixture.authority, &decoded);
    const rooted = try pair_node.authenticateRoot(
        &fixture.authority,
        &decoded,
        &fixture.root_pin,
    );
    const suite = try pair_node.prepareProtocolSuite();
    const prepared_pair = try pair_node.authenticatePairPrepared(
        &suite,
        &fixture.authority,
        &decoded,
    );
    const prepared_root = try pair_node.authenticateRootPrepared(
        &suite,
        &fixture.authority,
        &decoded,
        &fixture.root_pin,
    );
    const prepared_context = try pair_node.prepareRootContext(
        &suite,
        &fixture.authority,
        &fixture.root_pin,
    );
    const context_prepared_root = try pair_node.authenticateRootWithPreparedContext(
        &prepared_context,
        &fixture.authority,
        &decoded,
        &fixture.root_pin,
    );
    try std.testing.expectEqualDeep(pair, rooted.pair);
    try std.testing.expectEqualDeep(pair, prepared_pair);
    try std.testing.expectEqualDeep(rooted, prepared_root);
    try std.testing.expectEqualDeep(rooted, context_prepared_root);
    try std.testing.expectEqual(
        @as(usize, 39),
        pair_node.AuthenticationPermutationCostV1.suite_preparation,
    );
    try std.testing.expectEqual(
        @as(usize, 17),
        pair_node.AuthenticationPermutationCostV1.context_preparation,
    );
    try std.testing.expectEqual(
        @as(usize, 38),
        pair_node.AuthenticationPermutationCostV1.successful_context_prepared_root,
    );
    try std.testing.expectEqual(
        @as(usize, 55),
        pair_node.AuthenticationPermutationCostV1.successful_prepared_root,
    );
    try std.testing.expectEqual(
        @as(usize, 94),
        pair_node.AuthenticationPermutationCostV1.successful_convenience_root,
    );
    try std.testing.expect(
        pair_node.AuthenticationPermutationCostV1.successful_context_prepared_root <
            pair_node.AuthenticationPermutationCostV1.successful_prepared_root,
    );
    try std.testing.expectEqual(pair_node.FORMAT_ID_WORDS, pair.format_id);
    try std.testing.expectEqual(protocol.PROTOCOL_ID_WORDS, pair.protocol_id);
    try std.testing.expectEqual(@as(u32, 3), pair.pair_index);
    try std.testing.expectEqual(@as(u32, 6), pair.first_leaf_index);
    try std.testing.expectEqual(@as(u32, 2), pair.leaf_count);
    try std.testing.expectEqual(@as(u32, 8), pair.session_leaf_count);
    try std.testing.expect(!@hasField(pair_node.AuthenticatedPairV1, "record_id"));
    try std.testing.expectEqual(
        fixture.authority.context.aggregator_vk_id,
        pair.aggregator_vk_id,
    );
    try std.testing.expectEqual(
        protocol.challengeContextId(fixture.authority.context.session_id),
        pair.challenge_context_id,
    );

    var wire_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&encoded, &wire_sha256, .{});
    const record_id = try pair_node.recordId(&decoded);
    try std.testing.expectEqual(pair_node.FORMAT_ID_WORDS, pair_node.formatId());
    try std.testing.expectEqual(GOLDEN_WIRE_SHA256, wire_sha256);
    try std.testing.expectEqual(GOLDEN_RECORD_ID, record_id);
    try std.testing.expectEqual(GOLDEN_STATEMENT_ID, pair.identities.statement_id);
    try std.testing.expectEqual(GOLDEN_PROOF_ID, pair.identities.proof_id);
    try std.testing.expectEqual(GOLDEN_TRANSCRIPT_ID, pair.identities.transcript_id);
    try std.testing.expectEqual(GOLDEN_SUMMARY_ID, pair.identities.summary_id);
    try std.testing.expectEqual(GOLDEN_NODE_ID, pair.node_id);
}

test "R-009 prepared root context rejects independent authority and record mutations" {
    const fixture = try Fixture.init();
    const suite = try pair_node.prepareProtocolSuite();
    const prepared = try pair_node.prepareRootContext(
        &suite,
        &fixture.authority,
        &fixture.root_pin,
    );
    const canonical = try pair_node.authenticateRootWithPreparedContext(
        &prepared,
        &fixture.authority,
        &fixture.record,
        &fixture.root_pin,
    );
    try std.testing.expectEqualDeep(
        try pair_node.authenticateRootPrepared(
            &suite,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
        canonical,
    );

    var changed_authority = fixture.authority;
    changed_authority.context.job_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &changed_authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );
    changed_authority = fixture.authority;
    changed_authority.children[1].proof_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &changed_authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );

    var changed_pin = fixture.root_pin;
    changed_pin.expected_aggregator_vk_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &fixture.record,
            &changed_pin,
        ),
    );

    var changed_prepared = prepared;
    changed_prepared.authority_snapshot.context.execution_statement_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &changed_prepared,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );
    changed_prepared = prepared;
    changed_prepared.challenge_context_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &changed_prepared,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );
    changed_prepared = prepared;
    changed_prepared.authority_context_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &changed_prepared,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );
    changed_prepared = prepared;
    changed_prepared.root_pin_snapshot.expected_aggregator_vk_id[0] ^= 1;
    try std.testing.expectError(
        error.PreparedContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &changed_prepared,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );

    var changed_record = fixture.record;
    changed_record.children[0].challenge_context_id[0] ^= 1;
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &changed_record,
            &fixture.root_pin,
        ),
    );
    changed_record = fixture.record;
    changed_record.authority_context_id[0] ^= 1;
    changed_record.children[0].authority_context_id =
        changed_record.authority_context_id;
    changed_record.children[1].authority_context_id =
        changed_record.authority_context_id;
    try std.testing.expectError(
        error.AuthorityContextMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &changed_record,
            &fixture.root_pin,
        ),
    );
    changed_record = fixture.record;
    changed_record.aggregator_vk_id[0] ^= 1;
    changed_record.children[0].parent_vk_id = changed_record.aggregator_vk_id;
    changed_record.children[1].parent_vk_id = changed_record.aggregator_vk_id;
    try std.testing.expectError(
        error.AggregatorVkMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &changed_record,
            &fixture.root_pin,
        ),
    );
    changed_record = fixture.record;
    changed_record.children[1].proof_id[0] ^= 1;
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &changed_record,
            &fixture.root_pin,
        ),
    );
    changed_record = fixture.record;
    changed_record.children[0].event_count += 1;
    changed_record.children[1].event_count += 1;
    try std.testing.expectError(
        error.EventCountMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &changed_record,
            &fixture.root_pin,
        ),
    );
    changed_record = fixture.record;
    const delta = pair_node.SecureFelt{ .limbs = .{ 1, 0, 0, 0 } };
    changed_record.children[0].signed_relation_total =
        changed_record.children[0].signed_relation_total.add(delta);
    changed_record.children[1].signed_relation_total =
        changed_record.children[1].signed_relation_total.add(delta.neg());
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_node.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &changed_record,
            &fixture.root_pin,
        ),
    );
}

test "R-009 pair node rejects swapped omitted and duplicated children" {
    const fixture = try Fixture.init();

    var swapped = fixture.record;
    std.mem.swap(
        pair_node.ChildEvidenceV1,
        &swapped.children[0],
        &swapped.children[1],
    );
    try std.testing.expectError(error.ChildOrderMismatch, swapped.validate());

    var omitted_count = fixture.record;
    omitted_count.child_count = 1;
    try std.testing.expectError(error.ChildCountMismatch, omitted_count.validate());
    var omitted_flag = fixture.record;
    omitted_flag.children[1].present = 0;
    try std.testing.expectError(error.OmittedChild, omitted_flag.validate());

    var duplicate = fixture.record;
    duplicate.children[1].statement_id = duplicate.children[0].statement_id;
    duplicate.children[1].proof_id = duplicate.children[0].proof_id;
    duplicate.children[1].transcript_id = duplicate.children[0].transcript_id;
    duplicate.children[1].summary_id = duplicate.children[0].summary_id;
    try std.testing.expectError(error.DuplicateChildIdentity, duplicate.validate());

    var empty_identity = fixture.record;
    empty_identity.children[0].proof_id = .{0} ** channel.RATE;
    try std.testing.expectError(error.EmptyDigest, empty_identity.validate());
}

test "R-009 pair node re-derives session challenge and full authority context" {
    const fixture = try Fixture.init();

    var foreign_session = fixture.record;
    const session = id("foreign-session");
    for (&foreign_session.children) |*child| {
        child.session_id = session;
        child.challenge_context_id = protocol.challengeContextId(session);
    }
    // Both children agree and their local challenge derivation is internally
    // valid, but the verifier-owned session still rejects the record.
    try foreign_session.validate();
    try std.testing.expectError(
        error.SessionMismatch,
        pair_node.authenticatePair(&fixture.authority, &foreign_session),
    );

    var forged_context = fixture.record;
    const arbitrary = id("claimed-not-derived-context");
    for (&forged_context.children) |*child|
        child.challenge_context_id = arbitrary;
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        forged_context.validate(),
    );

    var mutually_agreed_context = fixture.record;
    const untrusted_context = id("children-agree-but-verifier-did-not-derive");
    mutually_agreed_context.authority_context_id = untrusted_context;
    for (&mutually_agreed_context.children) |*child|
        child.authority_context_id = untrusted_context;
    try mutually_agreed_context.validate();
    try std.testing.expectError(
        error.AuthorityContextMismatch,
        pair_node.authenticatePair(&fixture.authority, &mutually_agreed_context),
    );

    var foreign_authority = fixture.authority;
    foreign_authority.context.job_id = id("foreign-job");
    const foreign_context = try foreign_authority.context.contextId();
    for (&foreign_authority.children) |*child|
        child.authority_context_id = foreign_context;
    try foreign_authority.validate();
    try std.testing.expectError(
        error.AuthorityContextMismatch,
        pair_node.authenticatePair(&foreign_authority, &fixture.record),
    );

    var wrong_protocol = fixture.record;
    wrong_protocol.children[0].protocol_id = id("foreign-protocol");
    try std.testing.expectError(error.ProtocolMismatch, wrong_protocol.validate());
}

test "R-009 pair node injects parent VK and pins it only at the root" {
    const fixture = try Fixture.init();
    try std.testing.expectError(
        error.EmptyVerificationKey,
        pair_node.verificationKeyId(""),
    );

    var one_wrong_child = fixture.record;
    one_wrong_child.children[1].parent_vk_id = id("wrong-parent-vk");
    try std.testing.expectError(error.AggregatorVkMismatch, one_wrong_child.validate());

    var self_consistent_wrong_vk = fixture.record;
    const wrong_vk = id("self-consistent-wrong-vk");
    self_consistent_wrong_vk.aggregator_vk_id = wrong_vk;
    for (&self_consistent_wrong_vk.children) |*child| child.parent_vk_id = wrong_vk;
    try self_consistent_wrong_vk.validate();
    try std.testing.expectError(
        error.AggregatorVkMismatch,
        pair_node.authenticatePair(&fixture.authority, &self_consistent_wrong_vk),
    );

    var wrong_pin = fixture.root_pin;
    wrong_pin.expected_aggregator_vk_id = id("wrong-root-pin");
    try std.testing.expectError(
        error.RootVkMismatch,
        pair_node.authenticateRoot(&fixture.authority, &fixture.record, &wrong_pin),
    );
    var wrong_format_pin = fixture.root_pin;
    wrong_format_pin.format_id[0] +%= 1;
    try std.testing.expectError(error.FormatSealMismatch, wrong_format_pin.validate());
    var wrong_protocol_pin = fixture.root_pin;
    wrong_protocol_pin.protocol_id[0] +%= 1;
    try std.testing.expectError(error.ProtocolMismatch, wrong_protocol_pin.validate());
    _ = try pair_node.authenticateRoot(
        &fixture.authority,
        &fixture.record,
        &fixture.root_pin,
    );
}

test "R-009 pair node enforces kappa count padding and arithmetic bounds" {
    const fixture = try Fixture.init();

    var padded_header = fixture.record;
    padded_header.claimed_leaf_count = 3;
    try std.testing.expectError(error.LeafCountMismatch, padded_header.validate());

    var padded_child = fixture.record;
    padded_child.children[0].leaf_count = 2;
    padded_child.claimed_leaf_count = 3;
    try std.testing.expectError(error.CountPadding, padded_child.validate());

    var overflow = fixture.record;
    overflow.children[0].leaf_count = std.math.maxInt(u32);
    overflow.children[1].leaf_count = 1;
    try std.testing.expectError(error.LeafCountOverflow, overflow.validate());

    var exceeded = fixture.record;
    exceeded.children[0].leaf_count = pair_node.MAX_KAPPA;
    exceeded.children[1].leaf_count = 1;
    exceeded.claimed_leaf_count = pair_node.MAX_KAPPA + 1;
    try std.testing.expectError(error.KappaBoundExceeded, exceeded.validate());

    var wrong_bound = fixture.record;
    wrong_bound.kappa_bound -= 1;
    try std.testing.expectError(error.KappaBoundMismatch, wrong_bound.validate());

    var pair_overflow = fixture.record;
    pair_overflow.pair_index = pair_node.MAX_PAIR_INDEX + 1;
    try std.testing.expectError(error.PairIndexOutOfRange, pair_overflow.validate());

    var nonzero_padding = fixture.record;
    nonzero_padding.header_padding[2] = 1;
    try std.testing.expectError(error.NonZeroPadding, nonzero_padding.validate());
    nonzero_padding = fixture.record;
    nonzero_padding.children[0].padding = 1;
    try std.testing.expectError(error.NonZeroPadding, nonzero_padding.validate());

    var huge_count = fixture.authority;
    huge_count.context.event_count = std.math.maxInt(u64);
    try std.testing.expectError(error.EventCountOutOfRange, huge_count.validate());
}

test "R-009 pair node rejects noncanonical fields and unclosed summaries" {
    const fixture = try Fixture.init();

    var noncanonical_digest = fixture.record;
    noncanonical_digest.children[0].statement_id[3] = m31.Modulus;
    try std.testing.expectError(error.NonCanonicalField, noncanonical_digest.validate());

    var noncanonical_total = fixture.record;
    noncanonical_total.children[1].signed_relation_total.limbs[2] = m31.Modulus;
    try std.testing.expectError(error.NonCanonicalField, noncanonical_total.validate());

    var unclosed = fixture.record;
    unclosed.children[1].signed_relation_total.limbs[0] +%= 1;
    try std.testing.expectError(error.RelationNotClosed, unclosed.validate());

    var event_mismatch = fixture.record;
    event_mismatch.children[1].event_count += 1;
    try std.testing.expectError(error.EventCountMismatch, event_mismatch.validate());

    var encoded: [pair_node.ENCODED_LEN]u8 = undefined;
    try pair_node.encodeInto(&fixture.record, &encoded);
    // First child protocol digest begins 16 bytes into the child record.
    std.mem.writeInt(
        u32,
        encoded[pair_node.HEADER_ENCODED_LEN + 16 ..][0..4],
        m31.Modulus,
        .little,
    );
    var destination = fixture.record;
    const before = destination;
    try std.testing.expectError(
        error.NonCanonicalField,
        pair_node.decodeInto(&destination, &encoded),
    );
    try std.testing.expectEqualDeep(before, destination);
}

test "R-009 pair node requires verifier-owned child outputs and canonical empty totals" {
    const fixture = try Fixture.init();

    var fabricated = fixture.record;
    fabricated.children[0].statement_id = id("fabricated-statement");
    try fabricated.validate();
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_node.authenticatePair(&fixture.authority, &fabricated),
    );
    fabricated = fixture.record;
    fabricated.children[0].proof_id = id("fabricated-proof");
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_node.authenticatePair(&fixture.authority, &fabricated),
    );
    fabricated = fixture.record;
    fabricated.children[0].transcript_id = id("fabricated-transcript");
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_node.authenticatePair(&fixture.authority, &fabricated),
    );
    fabricated = fixture.record;
    fabricated.children[0].summary_id = id("fabricated-summary");
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_node.authenticatePair(&fixture.authority, &fabricated),
    );

    var same_core_identity = fixture.record;
    same_core_identity.children[1].statement_id =
        same_core_identity.children[0].statement_id;
    same_core_identity.children[1].proof_id =
        same_core_identity.children[0].proof_id;
    same_core_identity.children[1].transcript_id =
        same_core_identity.children[0].transcript_id;
    same_core_identity.children[1].summary_id = id("different-summary");
    try std.testing.expectError(
        error.DuplicateChildIdentity,
        same_core_identity.validate(),
    );

    var nonempty_with_empty_commitment = fixture.authority;
    nonempty_with_empty_commitment.context.public_call_commitment =
        protocol.emptyCallCommitment();
    try std.testing.expectError(
        error.NonEmptyEmptyCallCommitment,
        nonempty_with_empty_commitment.context.validate(),
    );

    var empty_context = fixture.authority.context;
    empty_context.event_count = 0;
    empty_context.public_call_commitment = protocol.emptyCallCommitment();
    try empty_context.validate();
    var nonzero_empty_total = fixture.record;
    for (&nonzero_empty_total.children) |*child| child.event_count = 0;
    try std.testing.expectError(
        error.RelationNotClosed,
        nonzero_empty_total.validate(),
    );
}

test "R-009 pair node binds exact session and event-count boundaries" {
    const fixture = try Fixture.init();

    var maximum_pair = fixture.authority.context;
    maximum_pair.session_leaf_count = pair_node.MAX_KAPPA;
    maximum_pair.pair_index = pair_node.MAX_PAIR_INDEX;
    try maximum_pair.validate();

    var outside_session = fixture.authority.context;
    outside_session.session_leaf_count = 4;
    outside_session.pair_index = 2;
    try std.testing.expectError(error.PairOutsideSession, outside_session.validate());

    var odd_session = fixture.authority.context;
    odd_session.session_leaf_count = 7;
    try std.testing.expectError(
        error.SessionLeafCountOutOfRange,
        odd_session.validate(),
    );

    var maximum_events = fixture.authority.context;
    maximum_events.event_count = m31.Modulus / 2;
    try maximum_events.validate();
    maximum_events.event_count += 1;
    try std.testing.expectError(
        error.EventCountOutOfRange,
        maximum_events.validate(),
    );
}

test "R-009 pair node identity folds bind each ordered evidence class" {
    const fixture = try Fixture.init();
    const canonical = try pair_node.authenticatePair(&fixture.authority, &fixture.record);

    var changed = fixture.record;
    changed.children[0].statement_id = id("changed-statement");
    var changed_authority = fixture.authority;
    changed_authority.children[0].statement_id = changed.children[0].statement_id;
    const statement = try pair_node.authenticatePair(&changed_authority, &changed);
    try std.testing.expect(!std.meta.eql(
        canonical.identities.statement_id,
        statement.identities.statement_id,
    ));
    try std.testing.expectEqual(canonical.identities.proof_id, statement.identities.proof_id);
    try std.testing.expectEqual(
        canonical.identities.transcript_id,
        statement.identities.transcript_id,
    );
    try std.testing.expectEqual(canonical.identities.summary_id, statement.identities.summary_id);

    changed = fixture.record;
    changed.children[1].proof_id = id("changed-proof");
    changed_authority = fixture.authority;
    changed_authority.children[1].proof_id = changed.children[1].proof_id;
    const proof = try pair_node.authenticatePair(&changed_authority, &changed);
    try std.testing.expect(!std.meta.eql(canonical.identities.proof_id, proof.identities.proof_id));

    changed = fixture.record;
    changed.children[0].transcript_id = id("changed-transcript");
    changed_authority = fixture.authority;
    changed_authority.children[0].transcript_id = changed.children[0].transcript_id;
    const transcript = try pair_node.authenticatePair(&changed_authority, &changed);
    try std.testing.expect(!std.meta.eql(
        canonical.identities.transcript_id,
        transcript.identities.transcript_id,
    ));

    changed = fixture.record;
    changed.children[1].summary_id = id("changed-summary");
    changed_authority = fixture.authority;
    changed_authority.children[1].summary_id = changed.children[1].summary_id;
    const summary = try pair_node.authenticatePair(&changed_authority, &changed);
    try std.testing.expect(!std.meta.eql(
        canonical.identities.summary_id,
        summary.identities.summary_id,
    ));
}

test {
    _ = @import("pair_node_test_continuation_1.zig");
}
