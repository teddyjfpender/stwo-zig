const std = @import("std");
const hash = @import("../aggregation/hash.zig");
const summary_mod = @import("relation_summary.zig");

const Digest = summary_mod.Digest;
const Fixture = struct {
    authority: summary_mod.PairAuthorityV1,
    summary: summary_mod.PairRelationSummaryV1,

    fn init(pair_index: u32, event_count: u64) Fixture {
        const session = testDigest("session");
        const challenge = testDigest("challenge");
        const relation_domain = summary_mod.canonicalRelationDomainDigest();
        const call_commitment = if (event_count == 0)
            hash.emptyCallCommitment()
        else
            testDigest("ordered-calls");
        const supply = if (event_count == 0)
            summary_mod.SecureFelt.zero()
        else
            summary_mod.SecureFelt{ .limbs = .{ 5, 7, 11, 13 } };
        const request = supply.neg();
        const first_leaf = pair_index * 2;
        const identities = [summary_mod.CHILD_COUNT]summary_mod.LeafIdentityV1{
            .{
                .statement_digest = testDigest("core-statement"),
                .proof_digest = testDigest("core-proof"),
                .transcript_digest = testDigest("core-transcript"),
            },
            .{
                .statement_digest = testDigest("provider-statement"),
                .proof_digest = testDigest("provider-proof"),
                .transcript_digest = testDigest("provider-transcript"),
            },
        };
        const authority = summary_mod.PairAuthorityV1{
            .session_digest = session,
            .challenge_context_digest = challenge,
            .relation_domain_digest = relation_domain,
            .pair_index = pair_index,
            .public_call_commitment = call_commitment,
            .event_count = event_count,
            .children = identities,
        };
        return .{
            .authority = authority,
            .summary = .{ .children = .{
                leaf(
                    session,
                    challenge,
                    relation_domain,
                    call_commitment,
                    identities[0],
                    first_leaf,
                    pair_index,
                    .left,
                    .core_component,
                    event_count,
                    request,
                ),
                leaf(
                    session,
                    challenge,
                    relation_domain,
                    call_commitment,
                    identities[1],
                    first_leaf + 1,
                    pair_index,
                    .right,
                    .poseidon2_precompile,
                    event_count,
                    supply,
                ),
            } },
        };
    }
};

test "R-007 relation summary V1 codec and digests are canonical" {
    const fixture = Fixture.init(3, 2);
    try summary_mod.validatePair(fixture.authority, fixture.summary);

    var encoded: [summary_mod.PAIR_ENCODED_LEN]u8 = undefined;
    try std.testing.expectEqual(
        summary_mod.PAIR_ENCODED_LEN,
        try summary_mod.encodePairInto(fixture.summary, &encoded),
    );
    const decoded = try summary_mod.decodePair(&encoded);
    try std.testing.expectEqualDeep(fixture.summary, decoded);
    try summary_mod.validatePair(fixture.authority, decoded);

    const allocated = try summary_mod.encodePairAlloc(
        std.testing.allocator,
        fixture.summary,
    );
    defer std.testing.allocator.free(allocated);
    try std.testing.expectEqualSlices(u8, &encoded, allocated);

    try std.testing.expectEqualSlices(
        u8,
        &summary_mod.MAGIC,
        encoded[summary_mod.HeaderOffset.magic..][0..summary_mod.MAGIC.len],
    );
    try std.testing.expectEqual(
        summary_mod.FORMAT_VERSION,
        readInt(u16, &encoded, summary_mod.HeaderOffset.version),
    );
    try std.testing.expectEqual(
        summary_mod.CHILD_COUNT,
        encoded[summary_mod.HeaderOffset.child_count],
    );
    try std.testing.expectEqual(
        summary_mod.RELATION_TOTAL_COUNT,
        encoded[summary_mod.HeaderOffset.relation_total_count],
    );
    const first = summary_mod.HEADER_ENCODED_LEN;
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(summary_mod.ChildPosition.left)),
        encoded[first + summary_mod.LeafOffset.child_position],
    );
    try std.testing.expectEqual(
        summary_mod.RELATION_SCHEMA_ID,
        readInt(
            u32,
            &encoded,
            first + summary_mod.LeafOffset.relation_total +
                summary_mod.RelationOffset.schema_id,
        ),
    );
    try std.testing.expectEqual(
        summary_mod.RELATION_ARITY,
        readInt(
            u16,
            &encoded,
            first + summary_mod.LeafOffset.relation_total +
                summary_mod.RelationOffset.arity,
        ),
    );

    const pair_digest = try summary_mod.pairDigest(fixture.summary);
    const left_digest = try summary_mod.leafDigest(fixture.summary.children[0]);
    const right_digest = try summary_mod.leafDigest(fixture.summary.children[1]);
    var wire_sha256: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&encoded, &wire_sha256, .{});
    try expectDigest(
        "a8d442a9f4c2247ad16065bee87325a0be8e30f9618b6db83ce04b984adc5548",
        summary_mod.canonicalRelationDomainDigest(),
    );
    try expectDigest(
        "5ffd6c876f1de01ad4b9ec8c25613cebcc1c8f7f8364e98e59de4a02a105b3d9",
        wire_sha256,
    );
    try expectDigest(
        "c9ee92cb1d2172c50e19290861dbf59ea7335ef2d545ed0f60adc15de9ca12df",
        pair_digest,
    );
    try expectDigest(
        "549b10e778f21e8ecb06a7fe204456e1dd5d06eaa275950635456a412f7b3a49",
        left_digest,
    );
    try expectDigest(
        "fd198c8df3c3fa7530fc4e7b4fa8872cc587463cb1bea98da16de33fb163164e",
        right_digest,
    );
    std.debug.print(
        "\n  R-007 V1: bytes={d} relation_domain={s} wire_sha256={s} " ++
            "pair_blake2s={s} left={s} right={s}\n",
        .{
            encoded.len,
            &std.fmt.bytesToHex(summary_mod.canonicalRelationDomainDigest(), .lower),
            &std.fmt.bytesToHex(wire_sha256, .lower),
            &std.fmt.bytesToHex(pair_digest, .lower),
            &std.fmt.bytesToHex(left_digest, .lower),
            &std.fmt.bytesToHex(right_digest, .lower),
        },
    );
    try std.testing.expect(!std.mem.eql(u8, &pair_digest, &left_digest));
    try std.testing.expect(!std.mem.eql(u8, &left_digest, &right_digest));
}

test "R-007 relation summary rejects swapped omitted duplicated and wrong-position children" {
    const fixture = Fixture.init(3, 2);

    var swapped = fixture.summary;
    std.mem.swap(
        summary_mod.LeafRelationSummaryV1,
        &swapped.children[0],
        &swapped.children[1],
    );
    try std.testing.expectError(
        error.ChildOrderMismatch,
        summary_mod.validatePair(fixture.authority, swapped),
    );

    var duplicated = fixture.summary;
    duplicated.children[1] = duplicated.children[0];
    duplicated.children[1].leaf_index += 1;
    duplicated.children[1].child_position = .right;
    duplicated.children[1].role = .poseidon2_precompile;
    try std.testing.expectError(
        error.DuplicateChildIdentity,
        summary_mod.validatePair(fixture.authority, duplicated),
    );

    var wrong_role = fixture.summary;
    wrong_role.children[0].role = .poseidon2_precompile;
    try std.testing.expectError(
        error.ChildOrderMismatch,
        summary_mod.validatePair(fixture.authority, wrong_role),
    );
    var wrong_position = fixture.summary;
    wrong_position.children[1].child_position = .left;
    try std.testing.expectError(
        error.ChildIndexMismatch,
        summary_mod.validatePair(fixture.authority, wrong_position),
    );

    var wrong_index = fixture.summary;
    wrong_index.children[0].leaf_index += 1;
    try std.testing.expectError(
        error.ChildIndexMismatch,
        summary_mod.validatePair(fixture.authority, wrong_index),
    );
    var split_pair = fixture.summary;
    split_pair.children[1].pair_index += 1;
    split_pair.children[1].leaf_index = split_pair.children[1].pair_index * 2 + 1;
    try std.testing.expectError(
        error.PairIndexMismatch,
        summary_mod.validatePair(fixture.authority, split_pair),
    );

    var bytes: [summary_mod.PAIR_ENCODED_LEN]u8 = undefined;
    _ = try summary_mod.encodePairInto(fixture.summary, &bytes);
    bytes[summary_mod.HeaderOffset.child_count] = 1;
    try std.testing.expectError(
        error.InvalidChildCount,
        summary_mod.decodePair(&bytes),
    );
}

test "R-007 relation summary rejects cross-session cross-domain and cross-transcript leaves" {
    const fixture = Fixture.init(3, 2);
    var one_session = fixture.summary;
    one_session.children[0].session_digest[0] ^= 1;
    try std.testing.expectError(
        error.SessionMismatch,
        summary_mod.validatePair(fixture.authority, one_session),
    );

    var foreign_session = fixture.summary;
    const other_session = testDigest("other-session");
    for (&foreign_session.children) |*child| child.session_digest = other_session;
    try std.testing.expectError(
        error.AuthoritySessionMismatch,
        summary_mod.validatePair(fixture.authority, foreign_session),
    );

    var foreign_challenge = fixture.summary;
    const other_challenge = testDigest("other-challenge");
    for (&foreign_challenge.children) |*child|
        child.challenge_context_digest = other_challenge;
    try std.testing.expectError(
        error.AuthorityChallengeContextMismatch,
        summary_mod.validatePair(fixture.authority, foreign_challenge),
    );

    var wrong_domain = fixture.summary;
    wrong_domain.children[0].relation_domain_digest[0] ^= 1;
    try std.testing.expectError(
        error.RelationDomainMismatch,
        summary_mod.validatePair(fixture.authority, wrong_domain),
    );

    var changed_transcript = fixture.summary;
    changed_transcript.children[0].leaf_transcript_digest[0] ^= 1;
    try std.testing.expectError(
        error.TranscriptIdentityMismatch,
        summary_mod.validatePair(fixture.authority, changed_transcript),
    );
    var swapped_transcripts = fixture.summary;
    std.mem.swap(
        Digest,
        &swapped_transcripts.children[0].leaf_transcript_digest,
        &swapped_transcripts.children[1].leaf_transcript_digest,
    );
    try std.testing.expectError(
        error.TranscriptIdentityMismatch,
        summary_mod.validatePair(fixture.authority, swapped_transcripts),
    );

    var changed_statement = fixture.summary;
    changed_statement.children[1].leaf_statement_digest[0] ^= 1;
    try std.testing.expectError(
        error.StatementIdentityMismatch,
        summary_mod.validatePair(fixture.authority, changed_statement),
    );
    var changed_proof = fixture.summary;
    changed_proof.children[1].leaf_proof_digest[0] ^= 1;
    try std.testing.expectError(
        error.ProofIdentityMismatch,
        summary_mod.validatePair(fixture.authority, changed_proof),
    );
}

test "R-007 relation summary rejects relation call and identity mutations" {
    const fixture = Fixture.init(3, 2);
    var changed_schema = fixture.summary;
    changed_schema.children[0].relation_totals[0].schema_id += 1;
    try std.testing.expectError(
        error.RelationSchemaMismatch,
        summary_mod.validatePair(fixture.authority, changed_schema),
    );
    var changed_version = fixture.summary;
    changed_version.children[0].relation_totals[0].schema_version += 1;
    try std.testing.expectError(
        error.RelationVersionMismatch,
        summary_mod.validatePair(fixture.authority, changed_version),
    );
    var changed_arity = fixture.summary;
    changed_arity.children[0].relation_totals[0].arity -= 1;
    try std.testing.expectError(
        error.RelationArityMismatch,
        summary_mod.validatePair(fixture.authority, changed_arity),
    );
    var changed_count = fixture.summary;
    changed_count.children[0].relation_totals[0].event_count += 1;
    try std.testing.expectError(
        error.ChildRelationCountMismatch,
        summary_mod.validatePair(fixture.authority, changed_count),
    );
    var foreign_count = fixture.summary;
    for (&foreign_count.children) |*child|
        child.relation_totals[0].event_count += 1;
    try std.testing.expectError(
        error.AuthorityCountMismatch,
        summary_mod.validatePair(fixture.authority, foreign_count),
    );

    var changed_call = fixture.summary;
    changed_call.children[0].public_call_commitment[0] ^= 1;
    try std.testing.expectError(
        error.CallCommitmentMismatch,
        summary_mod.validatePair(fixture.authority, changed_call),
    );
    var foreign_call = fixture.summary;
    const other_calls = testDigest("other-calls");
    for (&foreign_call.children) |*child|
        child.public_call_commitment = other_calls;
    try std.testing.expectError(
        error.AuthorityCallCommitmentMismatch,
        summary_mod.validatePair(fixture.authority, foreign_call),
    );

    var open_relation = fixture.summary;
    open_relation.children[1].relation_totals[0].signed_total.limbs[0] += 1;
    try std.testing.expectError(
        error.RelationNotClosed,
        summary_mod.validatePair(fixture.authority, open_relation),
    );
    var noncanonical = fixture.summary;
    noncanonical.children[0].relation_totals[0].signed_total.limbs[2] =
        summary_mod.M31_MODULUS;
    try std.testing.expectError(
        error.NonCanonicalM31,
        summary_mod.validatePair(fixture.authority, noncanonical),
    );
    var zero_proof = fixture.summary;
    zero_proof.children[0].leaf_proof_digest = .{0} ** 32;
    try std.testing.expectError(
        error.ZeroDigest,
        summary_mod.validatePair(fixture.authority, zero_proof),
    );
}

test "R-007 relation summary digest binds every externally admitted identity class" {
    const fixture = Fixture.init(3, 2);
    const canonical = try summary_mod.pairDigest(fixture.summary);

    var changed_session = fixture;
    const other_session = testDigest("digest-other-session");
    changed_session.authority.session_digest = other_session;
    for (&changed_session.summary.children) |*child|
        child.session_digest = other_session;
    try expectValidDifferentDigest(canonical, changed_session);

    var changed_challenge = fixture;
    const other_challenge = testDigest("digest-other-challenge");
    changed_challenge.authority.challenge_context_digest = other_challenge;
    for (&changed_challenge.summary.children) |*child|
        child.challenge_context_digest = other_challenge;
    try expectValidDifferentDigest(canonical, changed_challenge);

    var changed_statement = fixture;
    const other_statement = testDigest("digest-other-statement");
    changed_statement.authority.children[0].statement_digest = other_statement;
    changed_statement.summary.children[0].leaf_statement_digest = other_statement;
    try expectValidDifferentDigest(canonical, changed_statement);

    var changed_proof = fixture;
    const other_proof = testDigest("digest-other-proof");
    changed_proof.authority.children[1].proof_digest = other_proof;
    changed_proof.summary.children[1].leaf_proof_digest = other_proof;
    try expectValidDifferentDigest(canonical, changed_proof);

    var changed_transcript = fixture;
    const other_transcript = testDigest("digest-other-transcript");
    changed_transcript.authority.children[1].transcript_digest = other_transcript;
    changed_transcript.summary.children[1].leaf_transcript_digest = other_transcript;
    try expectValidDifferentDigest(canonical, changed_transcript);

    var changed_call = fixture;
    const other_call = testDigest("digest-other-call");
    changed_call.authority.public_call_commitment = other_call;
    for (&changed_call.summary.children) |*child|
        child.public_call_commitment = other_call;
    try expectValidDifferentDigest(canonical, changed_call);

    var changed_count = fixture;
    changed_count.authority.event_count = 3;
    for (&changed_count.summary.children) |*child|
        child.relation_totals[0].event_count = 3;
    try expectValidDifferentDigest(canonical, changed_count);

    var changed_position = fixture;
    changed_position.authority.pair_index = 4;
    for (&changed_position.summary.children, 0..) |*child, position| {
        child.pair_index = 4;
        child.leaf_index = @intCast(8 + position);
    }
    try expectValidDifferentDigest(canonical, changed_position);
}

test "R-007 relation summary decoder rejects malformed truncated and trailing frames" {
    const fixture = Fixture.init(3, 2);
    var canonical: [summary_mod.PAIR_ENCODED_LEN]u8 = undefined;
    _ = try summary_mod.encodePairInto(fixture.summary, &canonical);

    for (0..canonical.len) |cut| try std.testing.expectError(
        error.InvalidLength,
        summary_mod.decodePair(canonical[0..cut]),
    );
    var extended: [summary_mod.PAIR_ENCODED_LEN + 1]u8 = undefined;
    @memcpy(extended[0..canonical.len], &canonical);
    extended[canonical.len] = 0;
    try std.testing.expectError(
        error.InvalidLength,
        summary_mod.decodePair(&extended),
    );

    var malformed = canonical;
    malformed[summary_mod.HeaderOffset.magic] ^= 1;
    try std.testing.expectError(error.InvalidMagic, summary_mod.decodePair(&malformed));
    malformed = canonical;
    putInt(u16, &malformed, summary_mod.HeaderOffset.version, 2);
    try std.testing.expectError(
        error.UnsupportedVersion,
        summary_mod.decodePair(&malformed),
    );
    malformed = canonical;
    putInt(u16, &malformed, summary_mod.HeaderOffset.flags, 1);
    try std.testing.expectError(error.UnknownFlags, summary_mod.decodePair(&malformed));
    malformed = canonical;
    malformed[summary_mod.HeaderOffset.relation_total_count] = 2;
    try std.testing.expectError(
        error.InvalidRelationCount,
        summary_mod.decodePair(&malformed),
    );
    malformed = canonical;
    putInt(u16, &malformed, summary_mod.HeaderOffset.reserved, 1);
    try std.testing.expectError(
        error.NonZeroReserved,
        summary_mod.decodePair(&malformed),
    );

    const left = summary_mod.HEADER_ENCODED_LEN;
    malformed = canonical;
    malformed[left + summary_mod.LeafOffset.child_position] = 9;
    try std.testing.expectError(
        error.UnknownChildPosition,
        summary_mod.decodePair(&malformed),
    );
    malformed = canonical;
    malformed[left + summary_mod.LeafOffset.role] = 9;
    try std.testing.expectError(
        error.UnknownLeafRole,
        summary_mod.decodePair(&malformed),
    );
    malformed = canonical;
    putInt(u16, &malformed, left + summary_mod.LeafOffset.reserved, 1);
    try std.testing.expectError(
        error.NonZeroReserved,
        summary_mod.decodePair(&malformed),
    );
    malformed = canonical;
    putInt(
        u32,
        &malformed,
        left + summary_mod.LeafOffset.relation_total +
            summary_mod.RelationOffset.signed_total,
        summary_mod.M31_MODULUS,
    );
    try std.testing.expectError(
        error.NonCanonicalM31,
        summary_mod.decodePair(&malformed),
    );

    malformed = canonical;
    const right = left + summary_mod.LEAF_RECORD_ENCODED_LEN;
    @memcpy(
        malformed[right .. right + summary_mod.LEAF_RECORD_ENCODED_LEN],
        malformed[left .. left + summary_mod.LEAF_RECORD_ENCODED_LEN],
    );
    putInt(
        u32,
        &malformed,
        right + summary_mod.LeafOffset.leaf_index,
        fixture.summary.children[1].leaf_index,
    );
    malformed[right + summary_mod.LeafOffset.child_position] =
        @intFromEnum(summary_mod.ChildPosition.right);
    malformed[right + summary_mod.LeafOffset.role] =
        @intFromEnum(summary_mod.LeafRole.poseidon2_precompile);
    try std.testing.expectError(
        error.DuplicateChildIdentity,
        summary_mod.decodePair(&malformed),
    );
}

test "R-007 relation summary zero and maximum count boundaries are exact" {
    const empty = Fixture.init(0, 0);
    try summary_mod.validatePair(empty.authority, empty.summary);
    var bytes: [summary_mod.PAIR_ENCODED_LEN]u8 = undefined;
    _ = try summary_mod.encodePairInto(empty.summary, &bytes);
    try std.testing.expectEqualDeep(empty.summary, try summary_mod.decodePair(&bytes));

    var bad_empty_commitment = empty.summary;
    for (&bad_empty_commitment.children) |*child|
        child.public_call_commitment = testDigest("not-empty");
    try std.testing.expectError(
        error.NonCanonicalEmptyCallCommitment,
        summary_mod.validatePair(empty.authority, bad_empty_commitment),
    );
    var bad_empty_sum = empty.summary;
    bad_empty_sum.children[0].relation_totals[0].signed_total.limbs[0] = 1;
    try std.testing.expectError(
        error.NonZeroEmptyRelationTotal,
        summary_mod.validatePair(empty.authority, bad_empty_sum),
    );

    const maximum_count = (@as(u64, summary_mod.M31_MODULUS) - 1) / 2;
    const maximum = Fixture.init(summary_mod.MAX_PAIR_INDEX, maximum_count);
    try summary_mod.validatePair(maximum.authority, maximum.summary);
    var too_many = maximum;
    too_many.authority.event_count += 1;
    for (&too_many.summary.children) |*child|
        child.relation_totals[0].event_count += 1;
    try std.testing.expectError(
        error.CallCountOutOfRange,
        summary_mod.validatePair(too_many.authority, too_many.summary),
    );

    var nonempty_with_empty_commitment = Fixture.init(1, 1);
    nonempty_with_empty_commitment.authority.public_call_commitment =
        hash.emptyCallCommitment();
    for (&nonempty_with_empty_commitment.summary.children) |*child|
        child.public_call_commitment = hash.emptyCallCommitment();
    try std.testing.expectError(
        error.EmptyCommitmentForNonEmptyCalls,
        summary_mod.validatePair(
            nonempty_with_empty_commitment.authority,
            nonempty_with_empty_commitment.summary,
        ),
    );
}

test "R-007 relation summary encoding is atomic and releases every allocation failure" {
    const fixture = Fixture.init(3, 2);
    const sentinel: u8 = 0xa5;
    var destination = [_]u8{sentinel} ** summary_mod.PAIR_ENCODED_LEN;
    var invalid = fixture.summary;
    invalid.children[0].leaf_statement_digest = .{0} ** 32;
    try std.testing.expectError(
        error.ZeroDigest,
        summary_mod.encodePairInto(invalid, &destination),
    );
    try expectAll(sentinel, &destination);

    var short = [_]u8{sentinel} ** (summary_mod.PAIR_ENCODED_LEN - 1);
    try std.testing.expectError(
        error.IncorrectBufferLength,
        summary_mod.encodePairInto(fixture.summary, &short),
    );
    try expectAll(sentinel, &short);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn leaf(
    session: Digest,
    challenge: Digest,
    relation_domain: Digest,
    call_commitment: Digest,
    identity: summary_mod.LeafIdentityV1,
    leaf_index: u32,
    pair_index: u32,
    position: summary_mod.ChildPosition,
    role: summary_mod.LeafRole,
    event_count: u64,
    signed_total: summary_mod.SecureFelt,
) summary_mod.LeafRelationSummaryV1 {
    return .{
        .session_digest = session,
        .challenge_context_digest = challenge,
        .relation_domain_digest = relation_domain,
        .leaf_statement_digest = identity.statement_digest,
        .leaf_proof_digest = identity.proof_digest,
        .leaf_transcript_digest = identity.transcript_digest,
        .public_call_commitment = call_commitment,
        .leaf_index = leaf_index,
        .pair_index = pair_index,
        .child_position = position,
        .role = role,
        .relation_totals = .{.{
            .event_count = event_count,
            .signed_total = signed_total,
        }},
    };
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const fixture = Fixture.init(3, 2);
    const bytes = try summary_mod.encodePairAlloc(allocator, fixture.summary);
    defer allocator.free(bytes);
    try std.testing.expectEqual(summary_mod.PAIR_ENCODED_LEN, bytes.len);
    try std.testing.expectEqualDeep(fixture.summary, try summary_mod.decodePair(bytes));
}

fn testDigest(label: []const u8) Digest {
    return hash.hashDomain("stwo-zig/test/r007-relation-summary/v1\x00", label);
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    offset: usize,
) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

fn putInt(
    comptime T: type,
    bytes: []u8,
    offset: usize,
    value: T,
) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn expectAll(expected: u8, bytes: []const u8) !void {
    for (bytes) |byte| try std.testing.expectEqual(expected, byte);
}

fn expectValidDifferentDigest(expected: Digest, fixture: Fixture) !void {
    try summary_mod.validatePair(fixture.authority, fixture.summary);
    const actual = try summary_mod.pairDigest(fixture.summary);
    try std.testing.expect(!std.mem.eql(u8, &expected, &actual));
}

fn expectDigest(comptime expected_hex: *const [64]u8, actual: Digest) !void {
    var expected: Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqual(expected, actual);
}
