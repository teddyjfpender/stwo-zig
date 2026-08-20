const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_binary_verified_publication.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const global_closure = recursion.binary_global_closure_outer_source;
const pair_node = recursion.pair_node;
const protocol = recursion.protocol;
const roster = recursion.air.universal_roster;
const RelationDomain = @TypeOf(
    @as(global_closure.DomainClaimV1, undefined).domain,
);

test "binary verifier publication owns exact closure without capability escalation" {
    var fixture = try PublicationFixture.init();
    var publication: subject.VerifiedBinaryClosurePublicationV2 = undefined;
    try fixture.publish(&publication);
    try publication.validate();

    try std.testing.expectEqual(
        admission.ProofScope.verifier_subsystem,
        publication.source_scope,
    );
    try std.testing.expectEqual(
        subject.CohortSemanticsV1.split_role_v1,
        publication.cohort_semantics,
    );
    try std.testing.expectEqual(
        fixture.evidence.proof_id,
        publication.proof_id,
    );
    try std.testing.expectEqual(
        protocol.proofId("canonical-postcard-proof"),
        publication.proof_id,
    );
    try std.testing.expectEqual(
        @as(u32, "canonical-postcard-proof".len),
        publication.canonical_proof_byte_count,
    );
    try std.testing.expectEqual(
        shaDigest("canonical-postcard-proof"),
        publication.canonical_proof_sha_id,
    );
    try std.testing.expectEqual(
        fixture.pair.authority.context.execution_statement_id,
        publication.statement_id,
    );
    try std.testing.expectEqual(
        fixture.pair.authority.context.job_id,
        publication.job_id,
    );
    try std.testing.expectEqual(
        fixture.pair.authority.context.session_id,
        publication.session_id,
    );
    try std.testing.expectEqual(
        fixture.pair.authority.context.aggregator_vk_id,
        publication.recursive_parent_vk_id,
    );
    try std.testing.expectEqual(
        publication.authenticated_pair.pair.node_id,
        publication.cohort_id,
    );
    try std.testing.expectEqual(
        fixture.closure.closure_id,
        publication.closure_receipt_sha_id,
    );
    try std.testing.expectEqualDeep(
        fixture.closure,
        publication.closure_receipt,
    );
    try std.testing.expect(!publication.temporalV2Ready());
    try std.testing.expect(!publication.completeParentReady());
    try std.testing.expect(subject.PROTOCOL_SUBSTRATE_ONLY);
    try std.testing.expect(!subject.AUTHENTICATED_TEMPORAL_V2);
    try std.testing.expect(!subject.COMPLETE_PARENT_CAPABILITY);
    try std.testing.expectEqual(
        @as(usize, 0),
        subject.HEAP_ALLOCATIONS_PER_PUBLISH,
    );
    try std.testing.expectEqual(
        pair_node.AuthenticationPermutationCostV1.successful_context_prepared_root,
        subject.PAIR_SCALAR_POSEIDON_PERMUTATIONS_PER_PUBLISH,
    );
    try std.testing.expect(subject.OWNS_CLOSURE_RECEIPT_BY_VALUE);
    try std.testing.expect(!subject.BORROWED_STORAGE_AFTER_PUBLISH);
    try std.testing.expectEqual(
        @as(usize, 1),
        subject.CLOSURE_RECEIPT_COPIES_PER_PUBLISH,
    );

    // The publication owns its fixed receipt. Mutating every source after the
    // transaction cannot change the already published value.
    const owned = publication.closure_receipt;
    fixture.closure.closure_id[0] ^= 1;
    fixture.cohort_authority_sha_id[0] ^= 1;
    fixture.evidence.proof_id[0] ^= 1;
    try std.testing.expectEqualDeep(owned, publication.closure_receipt);
}

test "binary verifier canonical proof identity is chunk-boundary invariant" {
    const bytes = "canonical-postcard-proof";
    const direct = try subject.CanonicalProofIdentityV1.fromBytes(bytes);
    try std.testing.expectEqual(@as(u32, bytes.len), direct.byte_count);
    try std.testing.expectEqual(protocol.proofId(bytes), direct.proof_id);
    try std.testing.expectEqual(
        shaDigest(bytes),
        direct.canonical_proof_sha_id,
    );

    var split: usize = 0;
    while (split <= bytes.len) : (split += 1) {
        var stream = try subject.CanonicalProofIdentityStreamV1.init(bytes.len);
        try stream.writeAll(bytes[0..split]);
        try stream.writeAll(bytes[split..]);
        try std.testing.expectEqualDeep(direct, try stream.finalize());
    }

    var bytewise = try subject.CanonicalProofIdentityStreamV1.init(bytes.len);
    for (bytes) |byte| try bytewise.writeByte(byte);
    try std.testing.expectEqualDeep(direct, try bytewise.finalize());
    try std.testing.expectError(
        error.ProofIdentityAlreadyFinalized,
        bytewise.writeByte(0),
    );
    try std.testing.expectError(
        error.ProofIdentityAlreadyFinalized,
        bytewise.finalize(),
    );

    try std.testing.expectError(
        error.EmptyProofEncoding,
        subject.CanonicalProofIdentityStreamV1.init(0),
    );
    var short = try subject.CanonicalProofIdentityStreamV1.init(bytes.len);
    try short.writeAll(bytes[0 .. bytes.len - 1]);
    try std.testing.expectError(
        error.ProofEncodingLengthMismatch,
        short.finalize(),
    );
    var long = try subject.CanonicalProofIdentityStreamV1.init(bytes.len - 1);
    try std.testing.expectError(
        error.ProofEncodingLengthMismatch,
        long.writeAll(bytes),
    );
}

test "binary verifier publication rejects input mutation fleet atomically" {
    const fixture = try PublicationFixture.init();

    try std.testing.expectError(
        error.EmptyProofEncoding,
        subject.SuccessfulVerifierEvidenceV1.initFromSuccessfulVerifier(
            "",
            fixture.evidence.statement_id,
            fixture.evidence.verification_key_id,
            fixture.evidence.cohort_authority_sha_id,
        ),
    );

    var closure = fixture.closure;
    closure.closure_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &closure,
    );

    var evidence = fixture.evidence;
    evidence.canonical_proof_sha_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );
    evidence = fixture.evidence;
    evidence.proof_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );
    evidence = fixture.evidence;
    evidence.canonical_proof_byte_count += 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );
    evidence = fixture.evidence;
    evidence.source_scope = .complete_parent;
    try expectPublishRejectedAtomic(
        &fixture,
        &evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );

    var wrong_cohort = fixture.cohort_authority_sha_id;
    wrong_cohort[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &wrong_cohort,
        &fixture.closure,
    );

    var record = fixture.pair.record;
    record.children[0].proof_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );

    var root_pin = fixture.pair.root_pin;
    root_pin.expected_aggregator_vk_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );

    var authority = fixture.pair.authority;
    authority.context.session_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &fixture.prepared_pair,
        &authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );
    authority = fixture.pair.authority;
    authority.context.job_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &fixture.prepared_pair,
        &authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );

    var prepared_pair = fixture.prepared_pair;
    prepared_pair.authority_context_id[0] ^= 1;
    try expectPublishRejectedAtomic(
        &fixture,
        &fixture.evidence,
        &prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );

    const wrong_statement = try subject.SuccessfulVerifierEvidenceV1
        .initFromSuccessfulVerifier(
        "canonical-postcard-proof",
        nativeDigest("foreign-statement"),
        fixture.evidence.verification_key_id,
        fixture.evidence.cohort_authority_sha_id,
    );
    try expectPublishRejectedAtomic(
        &fixture,
        &wrong_statement,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );

    const wrong_vk = try subject.SuccessfulVerifierEvidenceV1
        .initFromSuccessfulVerifier(
        "canonical-postcard-proof",
        fixture.evidence.statement_id,
        nativeDigest("foreign-verification-key"),
        fixture.evidence.cohort_authority_sha_id,
    );
    try expectPublishRejectedAtomic(
        &fixture,
        &wrong_vk,
        &fixture.prepared_pair,
        &fixture.pair.authority,
        &fixture.pair.record,
        &fixture.pair.root_pin,
        &fixture.cohort_authority_sha_id,
        &fixture.closure,
    );
}

test "binary verifier publication rejects output capability and context mutation fleet" {
    var fixture = try PublicationFixture.init();
    var original: subject.VerifiedBinaryClosurePublicationV2 = undefined;
    try fixture.publish(&original);
    try original.validate();

    var changed = original;
    changed.closure_receipt_sha_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.authenticated_context_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.source_scope = .complete_parent;
    try expectValidationRejected(&changed);
    changed = original;
    changed.authenticated_temporal_v2 = true;
    try expectValidationRejected(&changed);
    changed = original;
    changed.complete_parent_capability = true;
    try expectValidationRejected(&changed);
    changed = original;
    changed.authenticated_pair.pair.node_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.recursive_parent_vk_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.session_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.job_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.lineage_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.verifier_context.job_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.cohort_authority_sha_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.canonical_proof_sha_id[0] ^= 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.canonical_proof_byte_count += 1;
    try expectValidationRejected(&changed);
    changed = original;
    changed.publication_id[0] ^= 1;
    try expectValidationRejected(&changed);
}

test "binary verifier publication rejects destination alias before validation" {
    const fixture = try PublicationFixture.init();
    comptime std.debug.assert(
        @sizeOf(subject.VerifiedBinaryClosurePublicationV2) >=
            @sizeOf(global_closure.ClosureReceiptV2),
    );
    comptime std.debug.assert(
        @alignOf(subject.VerifiedBinaryClosurePublicationV2) >=
            @alignOf(global_closure.ClosureReceiptV2),
    );

    var storage: subject.VerifiedBinaryClosurePublicationV2 = undefined;
    @memset(std.mem.asBytes(&storage), 0x7b);
    const aliased_closure: *global_closure.ClosureReceiptV2 = @ptrCast(
        @alignCast(&storage),
    );
    aliased_closure.* = fixture.closure;
    var before: [@sizeOf(subject.VerifiedBinaryClosurePublicationV2)]u8 =
        undefined;
    @memcpy(&before, std.mem.asBytes(&storage));
    try std.testing.expectError(
        error.AliasedDestination,
        subject.publishInto(
            &storage,
            &fixture.evidence,
            &fixture.prepared_pair,
            &fixture.pair.authority,
            &fixture.pair.record,
            &fixture.pair.root_pin,
            &fixture.cohort_authority_sha_id,
            aliased_closure,
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&storage));
}

const PublicationFixture = struct {
    pair: PairFixture,
    prepared_pair: subject.PreparedPairAuthorityV1,
    evidence: subject.SuccessfulVerifierEvidenceV1,
    cohort_authority_sha_id: subject.Sha256Digest,
    closure: global_closure.ClosureReceiptV2,

    fn init() !PublicationFixture {
        const pair = try PairFixture.init();
        const prepared_pair = try subject.preparePairAuthority(
            &pair.authority,
            &pair.root_pin,
        );
        const cohort_authority_sha_id = shaDigest("binary-cohort-authority");
        const evidence = try subject.SuccessfulVerifierEvidenceV1
            .initFromSuccessfulVerifier(
            "canonical-postcard-proof",
            pair.authority.context.execution_statement_id,
            pair.authority.context.aggregator_vk_id,
            cohort_authority_sha_id,
        );
        const closure_fixture = try ClosureFixtureV2.init();
        var workspace = global_closure.Workspace.init();
        var closure = global_closure.ClosureReceiptV2.fresh();
        try global_closure.fillIntoV2(
            &workspace,
            &closure_fixture.prepared,
            &closure_fixture.input,
            &closure,
        );
        return .{
            .pair = pair,
            .prepared_pair = prepared_pair,
            .evidence = evidence,
            .cohort_authority_sha_id = cohort_authority_sha_id,
            .closure = closure,
        };
    }

    fn publish(
        self: *const PublicationFixture,
        destination: *subject.VerifiedBinaryClosurePublicationV2,
    ) !void {
        return subject.publishInto(
            destination,
            &self.evidence,
            &self.prepared_pair,
            &self.pair.authority,
            &self.pair.record,
            &self.pair.root_pin,
            &self.cohort_authority_sha_id,
            &self.closure,
        );
    }
};

const PairFixture = struct {
    authority: pair_node.VerifierAuthorityV1,
    record: pair_node.PairNodeRecordV1,
    root_pin: pair_node.RootVkPinV1,

    fn init() !PairFixture {
        const context = pair_node.VerifierContextV1{
            .session_id = nativeDigest("publication-session"),
            .job_id = nativeDigest("publication-job"),
            .execution_statement_id = nativeDigest("publication-statement"),
            .public_call_commitment = nativeDigest("publication-calls"),
            .event_count = 2,
            .session_leaf_count = 8,
            .pair_index = 3,
            .aggregator_vk_id = try pair_node.verificationKeyId(
                "publication-aggregator-vk",
            ),
        };
        const challenge = try context.challengeContextId();
        const context_id = try context.contextId();
        const request = pair_node.SecureFelt{ .limbs = .{ 5, 7, 11, 13 } };
        const left = makeChild(
            context,
            challenge,
            context_id,
            .left,
            .core_request,
            "left",
            request,
        );
        const right = makeChild(
            context,
            challenge,
            context_id,
            .right,
            .poseidon2_provider,
            "right",
            request.neg(),
        );
        return .{
            .authority = .{
                .context = context,
                .children = .{ verifiedChild(left), verifiedChild(right) },
            },
            .record = .{
                .pair_index = context.pair_index,
                .first_leaf_index = context.pair_index * pair_node.CHILD_COUNT,
                .aggregator_vk_id = context.aggregator_vk_id,
                .authority_context_id = context_id,
                .children = .{ left, right },
            },
            .root_pin = .{
                .expected_aggregator_vk_id = context.aggregator_vk_id,
            },
        };
    }
};

fn makeChild(
    context: pair_node.VerifierContextV1,
    challenge: subject.NativeDigest,
    context_id: subject.NativeDigest,
    position: pair_node.ChildPosition,
    role: pair_node.ChildRole,
    label: []const u8,
    total: pair_node.SecureFelt,
) pair_node.ChildEvidenceV1 {
    const position_value: u32 = @intFromEnum(position);
    return .{
        .position = position,
        .role = role,
        .leaf_index = context.pair_index * pair_node.CHILD_COUNT + position_value,
        .pair_index = context.pair_index,
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = context.session_id,
        .challenge_context_id = challenge,
        .authority_context_id = context_id,
        .parent_vk_id = context.aggregator_vk_id,
        .statement_id = labelledNativeDigest(label, "statement"),
        .proof_id = labelledNativeDigest(label, "proof"),
        .transcript_id = labelledNativeDigest(label, "transcript"),
        .summary_id = labelledNativeDigest(label, "summary"),
        .event_count = context.event_count,
        .signed_relation_total = total,
    };
}

fn verifiedChild(child: pair_node.ChildEvidenceV1) pair_node.VerifiedChildV1 {
    return .{
        .position = child.position,
        .role = child.role,
        .leaf_index = child.leaf_index,
        .pair_index = child.pair_index,
        .leaf_count = child.leaf_count,
        .protocol_id = child.protocol_id,
        .session_id = child.session_id,
        .challenge_context_id = child.challenge_context_id,
        .authority_context_id = child.authority_context_id,
        .parent_vk_id = child.parent_vk_id,
        .statement_id = child.statement_id,
        .proof_id = child.proof_id,
        .transcript_id = child.transcript_id,
        .summary_id = child.summary_id,
        .event_count = child.event_count,
        .signed_relation_total = child.signed_relation_total,
    };
}

const ClosureFixtureV2 = struct {
    prepared: global_closure.PreparedAuthorityV2,
    input: global_closure.ClosureInputV2,

    fn init() !ClosureFixtureV2 {
        const range_value = testQm31(19, 23, 29, 31);
        const wire_value = testQm31(89, 97, 101, 103);
        const verifier_input_value = testQm31(107, 109, 113, 127);
        const base_prepared = try global_closure.prepareAuthority();
        var rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 =
            undefined;
        for (&rows, 0..) |*row, row_index|
            row.* = emptyClosureRow(@enumFromInt(row_index));

        setClosureDomain(&rows[0], .recursion_wire, testQm31(3, 5, 7, 11));
        setClosureDomain(
            &rows[1],
            .recursion_wire,
            testQm31(3, 5, 7, 11).neg(),
        );
        setClosureDomain(&rows[2], .recursion_wire, wire_value);
        setClosureDomain(
            &rows[3],
            .recursion_verifier_input_word,
            verifier_input_value,
        );
        setClosureDomain(&rows[10], .range_check_8_8, range_value);
        setClosureDomain(&rows[17], .recursion_step, testQm31(37, 41, 43, 47));
        setClosureDomain(
            &rows[18],
            .recursion_step,
            testQm31(37, 41, 43, 47).neg(),
        );
        setClosureDomain(&rows[20], .poseidon2, testQm31(53, 59, 61, 67));
        setClosureDomain(
            &rows[34],
            .poseidon2,
            testQm31(53, 59, 61, 67).neg(),
        );
        for (&rows) |*row| recomputeClosureRow(row);

        const provider = try global_closure.ProviderClaimV1.init(
            &base_prepared,
            shaDigest("publication-range-provider"),
            range_value.neg(),
        );
        const wire_evidence = global_closure.BoundaryEvidenceV2{
            .source_authority_id = shaDigest("publication-wire-source"),
            .snapshot_id = shaDigest("publication-wire-snapshot"),
            .tuple_provenance_id = shaDigest("publication-wire-provenance"),
            .tuple_count = 29,
            .claimed_sum = wire_value.neg(),
        };
        const verifier_input_evidence = global_closure.BoundaryEvidenceV2{
            .source_authority_id = shaDigest("publication-input-source"),
            .snapshot_id = shaDigest("publication-input-snapshot"),
            .tuple_provenance_id = shaDigest("publication-input-provenance"),
            .tuple_count = 16,
            .claimed_sum = verifier_input_value.neg(),
        };
        const authorities = try global_closure.BoundaryAuthoritiesV2.init(
            try global_closure.BoundarySourceV2.init(.wire, wire_evidence),
            try global_closure.BoundarySourceV2.init(
                .verifier_input,
                verifier_input_evidence,
            ),
        );
        const prepared = try global_closure.prepareAuthorityV2(authorities);
        const boundaries = try global_closure.PublicBoundariesV2.init(
            &prepared,
            wire_evidence,
            verifier_input_evidence,
        );
        return .{
            .prepared = prepared,
            .input = try global_closure.ClosureInputV2.init(
                &prepared,
                &rows,
                &provider,
                boundaries,
            ),
        };
    }
};

fn emptyClosureRow(row: roster.Component) global_closure.RowClaimsV1 {
    var domains: [global_closure.DOMAIN_COUNT]global_closure.DomainClaimV1 =
        undefined;
    for (&domains, 0..) |*claim, domain_index| claim.* = .{
        .active = 0,
        .domain = @enumFromInt(domain_index),
        .value = QM31.zero(),
    };
    return .{
        .row = row,
        .domains = domains,
        .claimed_sum = QM31.zero(),
    };
}

fn setClosureDomain(
    row: *global_closure.RowClaimsV1,
    domain: RelationDomain,
    value: QM31,
) void {
    const claim = &row.domains[@intFromEnum(domain)];
    claim.active = 1;
    claim.value = value;
}

fn recomputeClosureRow(row: *global_closure.RowClaimsV1) void {
    var total = QM31.zero();
    for (row.domains) |claim| total = total.add(claim.value);
    row.claimed_sum = total;
}

fn expectPublishRejectedAtomic(
    _: *const PublicationFixture,
    evidence: *const subject.SuccessfulVerifierEvidenceV1,
    prepared_pair: *const subject.PreparedPairAuthorityV1,
    authority: *const pair_node.VerifierAuthorityV1,
    record: *const pair_node.PairNodeRecordV1,
    root_pin: *const pair_node.RootVkPinV1,
    cohort_authority_sha_id: *const subject.Sha256Digest,
    closure: *const global_closure.ClosureReceiptV2,
) !void {
    var destination: subject.VerifiedBinaryClosurePublicationV2 = undefined;
    @memset(std.mem.asBytes(&destination), 0xa7);
    var before: [@sizeOf(subject.VerifiedBinaryClosurePublicationV2)]u8 =
        undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    if (subject.publishInto(
        &destination,
        evidence,
        prepared_pair,
        authority,
        record,
        root_pin,
        cohort_authority_sha_id,
        closure,
    )) |_| {
        return error.ExpectedPublicationRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));
}

fn expectValidationRejected(
    publication: *const subject.VerifiedBinaryClosurePublicationV2,
) !void {
    if (publication.validate()) |_| {
        return error.ExpectedPublicationValidationRejection;
    } else |_| {}
}

fn nativeDigest(label: []const u8) subject.NativeDigest {
    return channel.hashBytes(label, 0x4250_5445); // "BPTE"
}

fn labelledNativeDigest(
    left: []const u8,
    right: []const u8,
) subject.NativeDigest {
    var hash = channel.Channel{ .digest = nativeDigest(left) };
    const right_digest = nativeDigest(right);
    hash.mixU32s(&right_digest);
    return hash.digestWords();
}

fn shaDigest(label: []const u8) subject.Sha256Digest {
    var result: subject.Sha256Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}

fn testQm31(a: u32, b: u32, c: u32, d: u32) QM31 {
    return QM31.fromU32Unchecked(a, b, c, d);
}
