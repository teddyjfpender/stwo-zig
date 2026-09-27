//! Golden and adversarial evidence for the R-008 split leaf envelopes.

const std = @import("std");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const aggregation_fixture = @import("../../aggregation/test_fixture.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const subject = @import("split_leaf_statement.zig");

const Fixture = struct {
    manifest: aggregation_fixture.TwoLeafFixture,
    storage: [2]aggregation_manifest.PreparedLeafV1,
    session: aggregation_manifest.PreparedSessionV1,
    caller_identities: subject.VerifierOwnedLeafIdentitiesV1,
    provider_identities: subject.VerifierOwnedLeafIdentitiesV1,

    fn init(call_count: u64) !Fixture {
        var result: Fixture = undefined;
        result.manifest = aggregation_fixture.twoLeaves(call_count);
        result.session = try aggregation_manifest.prepare(
            result.manifest.view(),
            result.manifest.accepted,
            &result.storage,
        );
        result.session.leaves = &result.storage;
        const protocol = try subject.VerifierOwnedProtocolIdentityV1.canonical(
            result.manifest.accepted,
        );
        result.caller_identities = .{
            .protocol = protocol,
            .artifact = try artifactIdentity(
                result.manifest.descriptors[0],
                .guest_poseidon2_call_v1,
            ),
        };
        result.provider_identities = .{
            .protocol = protocol,
            .artifact = try artifactIdentity(
                result.manifest.descriptors[1],
                .guest_poseidon2_provider_compat_v1,
            ),
        };
        return result;
    }

    fn rebind(self: *Fixture) void {
        self.session.leaves = &self.storage;
    }
};

fn artifactIdentity(
    descriptor: aggregation_types.LeafDescriptorV1,
    kind: component_registry.Kind,
) !subject.VerifierOwnedArtifactIdentityV1 {
    return .{
        .role = descriptor.role,
        .air_artifact_digest = descriptor.leaf_air_artifact_digest,
        .preprocessed_root = descriptor.preprocessed_root,
        .component = try component_registry.Descriptor.canonical(
            kind,
            std.math.cast(u32, descriptor.guest_call_count) orelse
                return error.CallCountOutOfRange,
        ),
    };
}

const Statements = struct {
    caller: subject.CallerLeafStatementV1,
    provider: subject.ProviderLeafStatementV1,
};

fn statements(fixture: *const Fixture) !Statements {
    return .{
        .caller = try subject.CallerLeafStatementV1.init(
            &fixture.session,
            0,
            &fixture.caller_identities,
        ),
        .provider = try subject.ProviderLeafStatementV1.init(
            &fixture.session,
            1,
            &fixture.provider_identities,
        ),
    };
}

const TestWordSink = struct {
    words: [subject.word_count]u32 = undefined,
    len: usize = 0,

    pub fn writeWord(self: *TestWordSink, word: u32) !void {
        if (self.len >= self.words.len) return error.TooManyWords;
        self.words[self.len] = word;
        self.len += 1;
    }
};

fn verifyCanonicalPaths(
    statement: anytype,
    session: *const aggregation_manifest.PreparedSessionV1,
    identities: *const subject.VerifierOwnedLeafIdentitiesV1,
    magic: *const [8]u8,
    domain: []const u8,
) !void {
    const words = try statement.canonicalWords(session, identities);
    const bytes = try statement.encode(session, identities);
    try std.testing.expectEqual(@as(usize, subject.word_count), words.len);
    try std.testing.expectEqual(@as(usize, subject.encoded_size), bytes.len);
    try std.testing.expectEqualSlices(u8, magic, bytes[0..magic.len]);
    for (words, 0..) |word, index| {
        try std.testing.expectEqual(
            word,
            std.mem.readInt(u32, bytes[index * 4 ..][0..4], .little),
        );
    }

    var streamed: TestWordSink = .{};
    try statement.streamCanonicalWords(session, identities, &streamed);
    try std.testing.expectEqual(words.len, streamed.len);
    try std.testing.expectEqualSlices(u32, &words, streamed.words[0..streamed.len]);

    var independent = aggregation_hash.HashSink.init(domain);
    try independent.writeAll(&bytes);
    try std.testing.expectEqualSlices(
        u8,
        &independent.finalize(),
        &(try statement.sessionEnvelopeDigest(session, identities)),
    );
}

test "caller and provider are distinct typed envelopes over one canonical writer" {
    comptime {
        if (subject.CallerLeafStatementV1 == subject.ProviderLeafStatementV1)
            @compileError("role-separated leaf statement types collapsed");
    }
    var fixture = try Fixture.init(17);
    fixture.rebind();
    const pair = try statements(&fixture);

    try verifyCanonicalPaths(
        pair.caller,
        &fixture.session,
        &fixture.caller_identities,
        &subject.caller_magic,
        subject.caller_digest_domain,
    );
    try verifyCanonicalPaths(
        pair.provider,
        &fixture.session,
        &fixture.provider_identities,
        &subject.provider_magic,
        subject.provider_digest_domain,
    );
    try std.testing.expect(!aggregation_hash.eql(
        try pair.caller.sessionEnvelopeDigest(
            &fixture.session,
            &fixture.caller_identities,
        ),
        try pair.provider.sessionEnvelopeDigest(
            &fixture.session,
            &fixture.provider_identities,
        ),
    ));

    try std.testing.expect(subject.RESEARCH_ONLY);
    try std.testing.expect(!subject.VERIFIES_SPLIT_STARKS);
    try std.testing.expect(!subject.PROVES_ORDERED_CALL_COMMITMENT);
    try std.testing.expect(!subject.ACTIVATES_PRODUCTION_TRANSCRIPT);
}

const caller_wire_sha256 = [_]u8{
    0xbb, 0xe2, 0x90, 0x8d, 0xca, 0xa2, 0xb8, 0x31,
    0x56, 0x12, 0xe3, 0x6b, 0xe0, 0x15, 0x6e, 0xe3,
    0xa4, 0x26, 0x92, 0x9f, 0x67, 0xef, 0xaf, 0xc3,
    0xec, 0x5d, 0xd2, 0x5d, 0x9a, 0x68, 0x74, 0x5a,
};
const provider_wire_sha256 = [_]u8{
    0x8c, 0xea, 0x3d, 0x88, 0xf9, 0x28, 0xea, 0xea,
    0xb4, 0xb5, 0xd3, 0xad, 0x61, 0xab, 0x97, 0x31,
    0x0c, 0x2f, 0xdd, 0x41, 0x1f, 0x08, 0x3e, 0xd8,
    0x5d, 0xab, 0x37, 0xb1, 0x95, 0xa3, 0xa6, 0x6d,
};
const caller_envelope_blake2s = [_]u8{
    0x48, 0xaa, 0x71, 0x25, 0x19, 0xa6, 0xed, 0x5c,
    0x49, 0x80, 0xd1, 0x54, 0x7f, 0x73, 0x7c, 0xf2,
    0xf1, 0x51, 0xef, 0x97, 0x79, 0x16, 0xb1, 0x10,
    0x79, 0xcb, 0x4e, 0x08, 0x0f, 0x12, 0xd5, 0x1d,
};
const provider_envelope_blake2s = [_]u8{
    0x6a, 0xc0, 0xc7, 0x4d, 0xb4, 0xd8, 0x36, 0x0c,
    0x3e, 0x56, 0xf8, 0x65, 0xcf, 0xa1, 0xa0, 0xc4,
    0x80, 0x0b, 0x49, 0xc2, 0x3d, 0xc2, 0x1f, 0xcd,
    0xf5, 0x77, 0xba, 0x15, 0x66, 0x1e, 0xe8, 0xe8,
};

test "split leaf V1 wire and envelope identities are golden" {
    var fixture = try Fixture.init(17);
    fixture.rebind();
    const pair = try statements(&fixture);
    const caller_bytes = try pair.caller.encode(
        &fixture.session,
        &fixture.caller_identities,
    );
    const provider_bytes = try pair.provider.encode(
        &fixture.session,
        &fixture.provider_identities,
    );
    var caller_sha256: [32]u8 = undefined;
    var provider_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&caller_bytes, &caller_sha256, .{});
    std.crypto.hash.sha2.Sha256.hash(&provider_bytes, &provider_sha256, .{});
    const caller_blake2s = try pair.caller.sessionEnvelopeDigest(
        &fixture.session,
        &fixture.caller_identities,
    );
    const provider_blake2s = try pair.provider.sessionEnvelopeDigest(
        &fixture.session,
        &fixture.provider_identities,
    );

    try expectGolden("caller wire sha256", caller_wire_sha256, caller_sha256);
    try expectGolden(
        "provider wire sha256",
        provider_wire_sha256,
        provider_sha256,
    );
    try expectGolden(
        "caller envelope blake2s",
        caller_envelope_blake2s,
        caller_blake2s,
    );
    try expectGolden(
        "provider envelope blake2s",
        provider_envelope_blake2s,
        provider_blake2s,
    );

    // The descriptor field remains a distinct pre-session declaration, never
    // the session-bound envelope identity that would make R-007 cyclic.
    try std.testing.expect(!aggregation_hash.eql(
        pair.caller.body.descriptor_leaf_statement_digest,
        caller_blake2s,
    ));
    try std.testing.expect(!aggregation_hash.eql(
        pair.provider.body.descriptor_leaf_statement_digest,
        provider_blake2s,
    ));
}

fn expectGolden(label: []const u8, expected: [32]u8, actual: [32]u8) !void {
    if (!std.mem.eql(u8, &expected, &actual)) {
        const hex = std.fmt.bytesToHex(actual, .lower);
        std.debug.print("{s}={s}\n", .{ label, &hex });
    }
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

const BodyMutation = enum {
    magic_first,
    magic_second,
    format_version,
    encoded_word_count,
    flags,
    session_digest,
    challenge_context_digest,
    guest_z,
    guest_alpha,
    prepared_descriptor_digest,
    leaf_index,
    pair_index,
    leaf_role,
    descriptor_flags,
    descriptor_reserved,
    job_digest,
    descriptor_leaf_statement_digest,
    leaf_air_artifact_digest,
    preprocessed_root,
    main_root,
    guest_call_commitment,
    guest_call_count,
    proof_protocol_digest,
    execution_profile_id,
    relation_schema_version,
    execution_semantic_digest,
    relation_registry_digest,
    relation_schema_id,
    relation_arity,
    descriptor_reserved_tail,
    component_slot,
    component_kind,
    component_version,
    component_n_rows,
    component_log_size,
    component_preprocessed_columns,
    component_main_columns,
    component_interaction_columns,
    reserved_0,
    reserved_1,
    reserved_2,
    reserved_3,
};

fn mutateBody(body: *subject.LeafStatementBodyV1, mutation: BodyMutation) void {
    switch (mutation) {
        .magic_first => body.magic_words[0] ^= 1,
        .magic_second => body.magic_words[1] ^= 1,
        .format_version => body.format_version +%= 1,
        .encoded_word_count => body.encoded_word_count +%= 1,
        .flags => body.flags ^= 1,
        .session_digest => body.session_digest[0] ^= 1,
        .challenge_context_digest => body.challenge_context_digest[0] ^= 1,
        .guest_z => body.guest_z.limbs[0] +%= 1,
        .guest_alpha => body.guest_alpha.limbs[0] +%= 1,
        .prepared_descriptor_digest => body.prepared_descriptor_digest[0] ^= 1,
        .leaf_index => body.leaf_index +%= 1,
        .pair_index => body.pair_index +%= 1,
        .leaf_role => body.leaf_role = if (body.leaf_role == 1) 2 else 1,
        .descriptor_flags => body.descriptor_flags ^= 1,
        .descriptor_reserved => body.descriptor_reserved +%= 1,
        .job_digest => body.job_digest[0] ^= 1,
        .descriptor_leaf_statement_digest => body.descriptor_leaf_statement_digest[0] ^= 1,
        .leaf_air_artifact_digest => body.leaf_air_artifact_digest[0] ^= 1,
        .preprocessed_root => body.preprocessed_root[0] ^= 1,
        .main_root => body.main_root[0] ^= 1,
        .guest_call_commitment => body.guest_call_commitment[0] ^= 1,
        .guest_call_count => body.guest_call_count +%= 1,
        .proof_protocol_digest => body.proof_protocol_digest[0] ^= 1,
        .execution_profile_id => body.execution_profile_id +%= 1,
        .relation_schema_version => body.relation_schema_version +%= 1,
        .execution_semantic_digest => body.execution_semantic_digest[0] ^= 1,
        .relation_registry_digest => body.relation_registry_digest[0] ^= 1,
        .relation_schema_id => body.relation_schema_id +%= 1,
        .relation_arity => body.relation_arity +%= 1,
        .descriptor_reserved_tail => body.descriptor_reserved_tail +%= 1,
        .component_slot => body.component.slot = if (body.component.slot == .caller)
            .provider
        else
            .caller,
        .component_kind => body.component.kind = if (body.component.kind == .guest_poseidon2_call_v1) .guest_poseidon2_provider_compat_v1 else .guest_poseidon2_call_v1,
        .component_version => body.component.version +%= 1,
        .component_n_rows => body.component.n_rows +%= 1,
        .component_log_size => body.component.log_size +%= 1,
        .component_preprocessed_columns => body.component.preprocessed_columns +%= 1,
        .component_main_columns => body.component.main_columns +%= 1,
        .component_interaction_columns => body.component.interaction_columns +%= 1,
        .reserved_0 => body.reserved[0] = 1,
        .reserved_1 => body.reserved[1] = 1,
        .reserved_2 => body.reserved[2] = 1,
        .reserved_3 => body.reserved[3] = 1,
    }
}

fn expectRejectedBeforeWrite(
    statement: anytype,
    session: *const aggregation_manifest.PreparedSessionV1,
    identities: *const subject.VerifierOwnedLeafIdentitiesV1,
) !void {
    var destination = [_]u8{0xa5} ** subject.encoded_size;
    _ = statement.encodeInto(session, identities, &destination) catch {
        for (destination) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
        return;
    };
    return error.MutatedStatementAccepted;
}

fn exerciseBodyMutationMatrix(
    statement: anytype,
    session: *const aggregation_manifest.PreparedSessionV1,
    identities: *const subject.VerifierOwnedLeafIdentitiesV1,
) !void {
    inline for (std.meta.tags(BodyMutation)) |mutation| {
        var mutated = statement;
        mutateBody(&mutated.body, mutation);
        try expectRejectedBeforeWrite(mutated, session, identities);
    }
}

test "every caller and provider body field mutation rejects before emission" {
    var fixture = try Fixture.init(17);
    fixture.rebind();
    const pair = try statements(&fixture);
    try exerciseBodyMutationMatrix(
        pair.caller,
        &fixture.session,
        &fixture.caller_identities,
    );
    try exerciseBodyMutationMatrix(
        pair.provider,
        &fixture.session,
        &fixture.provider_identities,
    );
}

const AuthorityMutation = enum {
    proof_protocol_digest,
    execution_profile_id,
    execution_semantic_digest,
    relation_registry_digest,
    relation_schema_id,
    relation_schema_version,
    relation_arity,
    artifact_role,
    artifact_digest,
    preprocessed_root,
    component_slot,
    component_kind,
    component_version,
    component_n_rows,
    component_log_size,
    component_preprocessed_columns,
    component_main_columns,
    component_interaction_columns,
};

fn mutateAuthority(
    identities: *subject.VerifierOwnedLeafIdentitiesV1,
    mutation: AuthorityMutation,
) void {
    switch (mutation) {
        .proof_protocol_digest => identities.protocol.proof_protocol_digest[0] ^= 1,
        .execution_profile_id => identities.protocol.execution_profile_id +%= 1,
        .execution_semantic_digest => identities.protocol.execution_semantic_digest[0] ^= 1,
        .relation_registry_digest => identities.protocol.relation_registry_digest[0] ^= 1,
        .relation_schema_id => identities.protocol.relation_schema_id +%= 1,
        .relation_schema_version => identities.protocol.relation_schema_version +%= 1,
        .relation_arity => identities.protocol.relation_arity +%= 1,
        .artifact_role => identities.artifact.role = if (identities.artifact.role == .core_request) .poseidon2_provider else .core_request,
        .artifact_digest => identities.artifact.air_artifact_digest[0] ^= 1,
        .preprocessed_root => identities.artifact.preprocessed_root[0] ^= 1,
        .component_slot => identities.artifact.component.slot = if (identities.artifact.component.slot == .caller) .provider else .caller,
        .component_kind => identities.artifact.component.kind = if (identities.artifact.component.kind == .guest_poseidon2_call_v1) .guest_poseidon2_provider_compat_v1 else .guest_poseidon2_call_v1,
        .component_version => identities.artifact.component.version +%= 1,
        .component_n_rows => identities.artifact.component.n_rows +%= 1,
        .component_log_size => identities.artifact.component.log_size +%= 1,
        .component_preprocessed_columns => identities.artifact.component.preprocessed_columns +%= 1,
        .component_main_columns => identities.artifact.component.main_columns +%= 1,
        .component_interaction_columns => identities.artifact.component.interaction_columns +%= 1,
    }
}

fn exerciseAuthorityMutationMatrix(
    statement: anytype,
    session: *const aggregation_manifest.PreparedSessionV1,
    identities: subject.VerifierOwnedLeafIdentitiesV1,
) !void {
    inline for (std.meta.tags(AuthorityMutation)) |mutation| {
        var mutated = identities;
        mutateAuthority(&mutated, mutation);
        try expectRejectedBeforeWrite(statement, session, &mutated);
    }
}

test "every verifier-owned protocol and artifact identity mutation rejects" {
    var fixture = try Fixture.init(17);
    fixture.rebind();
    const pair = try statements(&fixture);
    try exerciseAuthorityMutationMatrix(
        pair.caller,
        &fixture.session,
        fixture.caller_identities,
    );
    try exerciseAuthorityMutationMatrix(
        pair.provider,
        &fixture.session,
        fixture.provider_identities,
    );
}

test "role swap cross-session commitment count and prepared-leaf mutations reject" {
    var fixture = try Fixture.init(17);
    fixture.rebind();
    const pair = try statements(&fixture);

    try std.testing.expectError(
        error.LeafRoleMismatch,
        subject.CallerLeafStatementV1.init(
            &fixture.session,
            1,
            &fixture.caller_identities,
        ),
    );
    try std.testing.expectError(
        error.LeafRoleMismatch,
        subject.ProviderLeafStatementV1.init(
            &fixture.session,
            0,
            &fixture.provider_identities,
        ),
    );
    try expectRejectedBeforeWrite(
        pair.caller,
        &fixture.session,
        &fixture.provider_identities,
    );
    try expectRejectedBeforeWrite(
        pair.provider,
        &fixture.session,
        &fixture.caller_identities,
    );

    // Change only the sibling descriptor: selected-leaf facts remain equal,
    // but the complete prepared-session digest changes and prevents replay.
    var other_manifest = aggregation_fixture.twoLeaves(17);
    other_manifest.descriptors[1].main_root[0] ^= 1;
    var other_storage: [2]aggregation_manifest.PreparedLeafV1 = undefined;
    var other_session = try aggregation_manifest.prepare(
        other_manifest.view(),
        other_manifest.accepted,
        &other_storage,
    );
    other_session.leaves = &other_storage;
    try expectRejectedBeforeWrite(
        pair.caller,
        &other_session,
        &fixture.caller_identities,
    );

    var other_count = try Fixture.init(18);
    other_count.rebind();
    try expectRejectedBeforeWrite(
        pair.caller,
        &other_count.session,
        &other_count.caller_identities,
    );
    try expectRejectedBeforeWrite(
        pair.provider,
        &other_count.session,
        &other_count.provider_identities,
    );

    var corrupt_commitment = try Fixture.init(17);
    corrupt_commitment.rebind();
    const corrupt_commitment_pair = try statements(&corrupt_commitment);
    corrupt_commitment.storage[0].descriptor.guest_call_commitment[0] ^= 1;
    try expectRejectedBeforeWrite(
        corrupt_commitment_pair.caller,
        &corrupt_commitment.session,
        &corrupt_commitment.caller_identities,
    );

    var corrupt_count = try Fixture.init(17);
    corrupt_count.rebind();
    const corrupt_count_pair = try statements(&corrupt_count);
    corrupt_count.storage[1].descriptor.guest_call_count +%= 1;
    try expectRejectedBeforeWrite(
        corrupt_count_pair.provider,
        &corrupt_count.session,
        &corrupt_count.provider_identities,
    );
}

test "empty call statements retain canonical R-007 empty commitment authority" {
    var fixture = try Fixture.init(0);
    fixture.rebind();
    const pair = try statements(&fixture);
    try pair.caller.validateAgainstSession(
        &fixture.session,
        &fixture.caller_identities,
    );
    try pair.provider.validateAgainstSession(
        &fixture.session,
        &fixture.provider_identities,
    );
    try std.testing.expectEqual(@as(u64, 0), pair.caller.body.guest_call_count);
    try std.testing.expectEqualSlices(
        u8,
        &aggregation_hash.emptyCallCommitment(),
        &pair.caller.body.guest_call_commitment,
    );
    try std.testing.expectEqual(
        component_registry.minimum_log_size,
        pair.caller.body.component.log_size,
    );
    try std.testing.expectEqual(
        component_registry.minimum_log_size,
        pair.provider.body.component.log_size,
    );
}

test "wrong-sized output is rejected without writing" {
    var fixture = try Fixture.init(1);
    fixture.rebind();
    const pair = try statements(&fixture);
    var short = [_]u8{0x5a} ** (subject.encoded_size - 1);
    try std.testing.expectError(
        error.IncorrectBufferLength,
        pair.caller.encodeInto(
            &fixture.session,
            &fixture.caller_identities,
            &short,
        ),
    );
    for (short) |byte| try std.testing.expectEqual(@as(u8, 0x5a), byte);
}
