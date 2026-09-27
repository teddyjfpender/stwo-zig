const std = @import("std");

const temporal = @import("temporal_pair_node.zig");
const protocol = @import("protocol.zig");
const span = @import("span_statement.zig");
const channel = @import("poseidon2_channel.zig");

test "temporal V2 authenticates adjacent complete leaves without cross-child repair" {
    const fixture = try twoSegmentFixture();
    try std.testing.expectEqual(
        temporal.ChildPosition.left,
        try temporal.positionForNextParent(fixture.statements[0]),
    );
    try std.testing.expectEqual(
        temporal.ChildPosition.right,
        try temporal.positionForNextParent(fixture.statements[1]),
    );
    const leaf_vk = id("segment-leaf-vk");
    const aggregator_vk = id("temporal-aggregator-vk");
    const session_id = id("session");
    const children = [2]temporal.VerifiedChildV2{
        try completeChild(
            .left,
            .segment_leaf,
            fixture.statements[0],
            session_id,
            leaf_vk,
            aggregator_vk,
            "left",
        ),
        try completeChild(
            .right,
            .segment_leaf,
            fixture.statements[1],
            session_id,
            leaf_vk,
            aggregator_vk,
            "right",
        ),
    };
    const context = try contextFor(
        session_id,
        leaf_vk,
        aggregator_vk,
        fixture.parent,
    );
    const authority = temporal.VerifierAuthorityV2{
        .context = context,
        .children = children,
    };
    try authority.validate();
    const record = try temporal.recordFromAuthority(&authority);
    try record.validate();
    const pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = aggregator_vk,
    };
    const authenticated = try temporal.authenticateRoot(
        &authority,
        &record,
        &pin,
    );
    const prepared = try temporal.prepareRootContext(&authority, &pin);
    const hot = try temporal.authenticateRootWithPreparedContext(
        &prepared,
        &authority,
        &record,
        &pin,
    );
    try std.testing.expectEqualDeep(record, prepared.record_snapshot);
    try std.testing.expectEqual(authenticated, hot);
    try std.testing.expectEqualDeep(
        try authority.context.id(),
        prepared.result.pair.context_id,
    );
    try std.testing.expectEqualDeep(
        try authority.children[0].id(),
        prepared.result.pair.child_ids[0],
    );
    try std.testing.expectEqualDeep(
        try authority.children[1].id(),
        prepared.result.pair.child_ids[1],
    );
    try std.testing.expectEqualDeep(
        try record.id(),
        prepared.result.pair.record_id,
    );

    // Captured from the pre-dedup implementation. The optimized one-pass
    // derivation must preserve every externally observable identity exactly.
    const golden = PreDedupIdentityGoldenV2{};
    try std.testing.expectEqualDeep(
        golden.format_id,
        prepared.result.pair.format_id,
    );
    try std.testing.expectEqualDeep(
        golden.parent_statement_id,
        prepared.result.pair.parent_statement_id,
    );
    try std.testing.expectEqualDeep(
        golden.child_ids,
        prepared.result.pair.child_ids,
    );
    try std.testing.expectEqualDeep(
        golden.context_id,
        prepared.result.pair.context_id,
    );
    try std.testing.expectEqualDeep(
        golden.node_id,
        prepared.result.pair.node_id,
    );
    try std.testing.expectEqualDeep(
        golden.record_id,
        prepared.result.pair.record_id,
    );
    try std.testing.expectEqual(@as(u8, 1), authenticated.pair.parent_height);
    try std.testing.expectEqual(@as(u64, 0), authenticated.pair.parent_node_index);
    try std.testing.expectEqual(
        context.expected_parent_statement_id,
        authenticated.pair.parent_statement_id,
    );
    try std.testing.expect(!temporal.CROSS_CHILD_RELATION_REPAIR);
    try std.testing.expect(temporal.TEMPORAL_FOLD_AUTHORITY);
    try std.testing.expectEqual(
        @as(usize, 0),
        temporal.HOT_AUTHENTICATION_HEAP_ALLOCATIONS,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        temporal.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS,
    );
    try std.testing.expectEqual(
        @as(usize, 281),
        temporal.PreparationPermutationCostV2.successful_complete_pair,
    );
    try std.testing.expectEqual(
        @as(usize, 499),
        temporal.PreparationPermutationCostV2.historical_complete_pair,
    );
    try std.testing.expectEqual(
        @as(usize, 218),
        temporal.PreparationPermutationCostV2.eliminated_complete_pair,
    );
    try std.testing.expectEqual(
        @as(usize, 276),
        temporal.PreparationPermutationCostV2.successful_tail_pair,
    );
    try std.testing.expectEqual(
        @as(usize, 213),
        temporal.PreparationPermutationCostV2.eliminated_tail_pair,
    );

    var changed = authority;
    changed.children[0].proof_id[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        temporal.authenticateRootWithPreparedContext(
            &prepared,
            &changed,
            &record,
            &pin,
        ),
    );
}

test "temporal V2 executed permutation audit pins cold and prepared-hot paths" {
    const fixture = try completePairAuthorityFixture();

    var cold_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&cold_audit);
    defer temporal.test_support.cancel(&cold_audit);
    const prepared = try temporal.prepareRootContext(
        &fixture.authority,
        &fixture.pin,
    );
    const cold = try temporal.test_support.finish(&cold_audit);
    try std.testing.expectEqual(@as(usize, 13), cold.hash_invocations);
    try std.testing.expectEqual(
        temporal.PreparationPermutationCostV2.successful_complete_pair,
        cold.scalar_poseidon_permutations,
    );

    // A nontrivial repetition count makes this a path regression rather than
    // evidence about one lucky call.  Every returned node remains observable,
    // while the dynamic counter proves that no hashing site executed.
    const hot_iterations: usize = 4_096;
    var hot_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&hot_audit);
    defer temporal.test_support.cancel(&hot_audit);
    var checksum: u32 = 0;
    for (0..hot_iterations) |_| {
        const authenticated = try temporal.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
        std.mem.doNotOptimizeAway(&authenticated);
        checksum ^= authenticated.pair.node_id[0];
    }
    std.mem.doNotOptimizeAway(&checksum);
    const hot = try temporal.test_support.finish(&hot_audit);
    try std.testing.expectEqual(@as(usize, 0), hot.hash_invocations);
    try std.testing.expectEqual(
        @as(usize, 0),
        hot.scalar_poseidon_permutations,
    );

    // The mutation-rejection side of the same hot boundary must remain
    // hash-free as well; it compares the complete by-value snapshots before
    // returning the cached result.
    var changed = fixture.authority;
    changed.children[1].capture_id[0] ^= 1;
    var rejection_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&rejection_audit);
    defer temporal.test_support.cancel(&rejection_audit);
    try std.testing.expectError(
        error.AuthorityMismatch,
        temporal.authenticateRootWithPreparedContext(
            &prepared,
            &changed,
            &prepared.record_snapshot,
            &fixture.pin,
        ),
    );
    const rejection = try temporal.test_support.finish(&rejection_audit);
    try std.testing.expectEqual(@as(usize, 0), rejection.hash_invocations);
    try std.testing.expectEqual(
        @as(usize, 0),
        rejection.scalar_poseidon_permutations,
    );
}

test "temporal V2 prepared pair wall-time observation" {
    const allocator = std.testing.allocator;
    const raw_iterations = std.process.getEnvVarOwned(
        allocator,
        "STWO_TEMPORAL_PAIR_BENCH_ITERATIONS",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(raw_iterations);
    const iterations = try std.fmt.parseUnsigned(usize, raw_iterations, 10);
    if (iterations == 0 or iterations > 1_000_000)
        return error.InvalidBenchmarkIterations;

    const fixture = try completePairAuthorityFixture();
    const prepared = try temporal.prepareRootContext(
        &fixture.authority,
        &fixture.pin,
    );
    const expected = prepared.result;
    for (0..32) |_| {
        _ = try temporal.authenticateRoot(
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
        _ = try temporal.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
    }

    // ABBA ordering reduces one-way thermal bias.  This remains a focused
    // native microbenchmark, not a recursive-proof throughput claim.
    var checksum: u32 = 0;
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const result = try temporal.authenticateRoot(
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[0];
    }
    const cold_first_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try temporal.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[1];
    }
    const hot_first_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try temporal.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[2];
    }
    const hot_second_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try temporal.authenticateRoot(
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[3];
    }
    const cold_second_ns = timer.read();
    std.mem.doNotOptimizeAway(&checksum);

    const samples: u64 = @intCast(2 * iterations);
    const cold_ns = try std.math.add(u64, cold_first_ns, cold_second_ns);
    const hot_ns = try std.math.add(u64, hot_first_ns, hot_second_ns);
    const cold_ns_per_op = cold_ns / samples;
    const hot_ns_per_op = hot_ns / samples;
    const speedup_basis_points = if (hot_ns_per_op == 0)
        @as(u64, 0)
    else
        cold_ns_per_op * 10_000 / hot_ns_per_op;
    try std.testing.expectEqualDeep(
        expected,
        try temporal.authenticateRootWithPreparedContext(
            &prepared,
            &fixture.authority,
            &prepared.record_snapshot,
            &fixture.pin,
        ),
    );
    std.debug.print(
        "\n  TPV2_PAIR_WALL iterations={d} cold_ns_per_op={d} " ++
            "hot_ns_per_op={d} speedup_basis_points={d} " ++
            "historical_permutations={d} cold_permutations={d} " ++
            "eliminated_cold_permutations={d} hot_permutations={d}\n",
        .{
            samples,
            cold_ns_per_op,
            hot_ns_per_op,
            speedup_basis_points,
            temporal.PreparationPermutationCostV2.historical_complete_pair,
            temporal.PreparationPermutationCostV2.successful_complete_pair,
            temporal.PreparationPermutationCostV2.eliminated_complete_pair,
            temporal.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS,
        },
    );
}

const PreDedupIdentityGoldenV2 = struct {
    format_id: temporal.Digest = .{
        520_654_604,
        986_328_038,
        551_615_801,
        1_835_763_874,
        1_762_121_901,
        892_607_946,
        1_732_215_404,
        453_011_288,
    },
    parent_statement_id: temporal.Digest = .{
        1_787_018_554,
        244_148_674,
        1_932_243_354,
        532_758_354,
        727_017_214,
        1_658_569_046,
        82_584_027,
        1_686_799_164,
    },
    child_ids: [2]temporal.Digest = .{
        .{
            454_009_202,
            1_320_378_556,
            502_373_365,
            51_490_152,
            1_274_785_376,
            779_236_619,
            1_208_765_582,
            143_972_899,
        },
        .{
            580_856_053,
            766_649_446,
            1_144_956_234,
            36_043_745,
            1_287_503_385,
            977_210_583,
            1_033_563_855,
            113_065_211,
        },
    },
    context_id: temporal.Digest = .{
        2_139_240_048,
        1_455_914_784,
        1_312_111_427,
        1_164_362_810,
        450_068_260,
        278_113_698,
        1_425_221_142,
        199_400_971,
    },
    node_id: temporal.Digest = .{
        2_030_429_436,
        1_349_054_288,
        1_030_137_174,
        1_507_637_417,
        1_057_732_085,
        1_495_199_406,
        1_949_786_907,
        2_067_078_199,
    },
    record_id: temporal.Digest = .{
        998_985_042,
        1_056_477_760,
        399_482_333,
        1_447_726_423,
        512_023_603,
        951_737_308,
        578_124_671,
        1_272_025_589,
    },
};

test "temporal V2 rejects authority, closure, ordering, kind, and root mutations" {
    const fixture = try twoSegmentFixture();
    const leaf_vk = id("segment-leaf-vk");
    const aggregator_vk = id("temporal-aggregator-vk");
    const session_id = id("session");
    var authority = temporal.VerifierAuthorityV2{
        .context = try contextFor(
            session_id,
            leaf_vk,
            aggregator_vk,
            fixture.parent,
        ),
        .children = .{
            try completeChild(
                .left,
                .segment_leaf,
                fixture.statements[0],
                session_id,
                leaf_vk,
                aggregator_vk,
                "left",
            ),
            try completeChild(
                .right,
                .segment_leaf,
                fixture.statements[1],
                session_id,
                leaf_vk,
                aggregator_vk,
                "right",
            ),
        },
    };
    const original = authority;
    const record = try temporal.recordFromAuthority(&authority);

    authority.children[0].closure_value[0] = 1;
    try std.testing.expectError(error.ClosureMismatch, authority.validate());
    authority = original;

    authority.children[0].position = .right;
    try std.testing.expectError(error.ChildOrderMismatch, authority.validate());
    authority = original;

    authority.children[0].kind = .binary_node;
    try std.testing.expectError(error.ChildKindMismatch, authority.validate());
    authority = original;

    authority.children[1].verification_key_id = aggregator_vk;
    try std.testing.expectError(error.VerificationKeyMismatch, authority.validate());
    authority = original;

    authority.context.expected_parent_statement_id = id("wrong-parent");
    try std.testing.expectError(error.StatementMismatch, authority.validate());
    authority = original;

    var mutated_record = record;
    mutated_record.node_id[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        temporal.authenticateRoot(
            &authority,
            &mutated_record,
            &.{ .expected_aggregator_vk_id = aggregator_vk },
        ),
    );
    try std.testing.expectError(
        error.RootVkMismatch,
        temporal.authenticateRoot(
            &authority,
            &record,
            &.{ .expected_aggregator_vk_id = id("wrong-vk") },
        ),
    );
}

test "temporal V2 admits only protocol-owned trailing empty padding" {
    const fixture = try threeSegmentTailFixture();
    const leaf_vk = id("segment-leaf-vk");
    const aggregator_vk = id("temporal-aggregator-vk");
    const session_id = id("session");
    const context = try contextFor(
        session_id,
        leaf_vk,
        aggregator_vk,
        fixture.parent,
    );
    var empty = try emptyChild(
        .right,
        fixture.statements[1],
        session_id,
        aggregator_vk,
    );
    var authority = temporal.VerifierAuthorityV2{
        .context = context,
        .children = .{
            try completeChild(
                .left,
                .segment_leaf,
                fixture.statements[0],
                session_id,
                leaf_vk,
                aggregator_vk,
                "tail",
            ),
            empty,
        },
    };
    try authority.validate();

    empty.proof_present = true;
    authority.children[1] = empty;
    try std.testing.expectError(error.ChildKindMismatch, authority.validate());

    empty.proof_present = false;
    empty.proof_id = id("smuggled-proof");
    authority.children[1] = empty;
    try std.testing.expectError(error.EmptyChildHasProof, authority.validate());
}

const Fixture = struct {
    statements: [2]span.SpanStatement,
    parent: span.SpanStatement,
};

const CompletePairAuthorityFixture = struct {
    authority: temporal.VerifierAuthorityV2,
    pin: temporal.RootVkPinV2,
};

fn completePairAuthorityFixture() !CompletePairAuthorityFixture {
    const fixture = try twoSegmentFixture();
    const leaf_vk = id("segment-leaf-vk");
    const aggregator_vk = id("temporal-aggregator-vk");
    const session_id = id("session");
    return .{
        .authority = .{
            .context = try contextFor(
                session_id,
                leaf_vk,
                aggregator_vk,
                fixture.parent,
            ),
            .children = .{
                try completeChild(
                    .left,
                    .segment_leaf,
                    fixture.statements[0],
                    session_id,
                    leaf_vk,
                    aggregator_vk,
                    "left",
                ),
                try completeChild(
                    .right,
                    .segment_leaf,
                    fixture.statements[1],
                    session_id,
                    leaf_vk,
                    aggregator_vk,
                    "right",
                ),
            },
        },
        .pin = .{ .expected_aggregator_vk_id = aggregator_vk },
    };
}

fn twoSegmentFixture() !Fixture {
    const s0 = try machineState(0, "state-0");
    const s1 = try machineState(4, "state-1");
    const s2 = try machineState(8, "state-2");
    const input = id("public-input");
    const output = id("public-output");
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            id("program"),
            s0,
            s2,
            input,
            output,
            20,
        ),
        2,
    );
    const statements = [2]span.SpanStatement{
        try span.SpanStatement.segmentLeaf(
            job,
            0,
            try span.ExecutedSpan.init(
                0,
                1,
                0,
                10,
                s0,
                s1,
                try span.EdgeClaim.present(input),
                span.EdgeClaim.absent(),
            ),
        ),
        try span.SpanStatement.segmentLeaf(
            job,
            1,
            try span.ExecutedSpan.init(
                1,
                1,
                10,
                10,
                s1,
                s2,
                span.EdgeClaim.absent(),
                try span.EdgeClaim.present(output),
            ),
        ),
    };
    return .{
        .statements = statements,
        .parent = try span.SpanStatement.fold(statements[0], statements[1]),
    };
}

fn threeSegmentTailFixture() !Fixture {
    const s0 = try machineState(0, "state-0");
    const s2 = try machineState(8, "state-2");
    const s3 = try machineState(12, "state-3");
    const input = id("public-input");
    const output = id("public-output");
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            id("program"),
            s0,
            s3,
            input,
            output,
            30,
        ),
        3,
    );
    const statements = [2]span.SpanStatement{
        try span.SpanStatement.segmentLeaf(
            job,
            2,
            try span.ExecutedSpan.init(
                2,
                1,
                20,
                10,
                s2,
                s3,
                span.EdgeClaim.absent(),
                try span.EdgeClaim.present(output),
            ),
        ),
        try span.SpanStatement.emptyLeaf(job, 3),
    };
    return .{
        .statements = statements,
        .parent = try span.SpanStatement.fold(statements[0], statements[1]),
    };
}

fn contextFor(
    session_id: temporal.Digest,
    leaf_vk: temporal.Digest,
    aggregator_vk: temporal.Digest,
    parent: span.SpanStatement,
) !temporal.VerifierContextV2 {
    const words = try parent.canonicalWords();
    return .{
        .session_id = session_id,
        .job_id = try temporal.jobId(&words),
        .segment_leaf_vk_id = leaf_vk,
        .aggregator_vk_id = aggregator_vk,
        .parent_node_index = parent.slots.nodeIndex(),
        .parent_height = parent.slots.height,
        .expected_parent_statement_id = statementId(&words),
    };
}

fn completeChild(
    position: temporal.ChildPosition,
    kind: temporal.ProofKind,
    statement: span.SpanStatement,
    session_id: temporal.Digest,
    vk_id: temporal.Digest,
    parent_vk_id: temporal.Digest,
    label: []const u8,
) !temporal.VerifiedChildV2 {
    const words = try statement.canonicalWords();
    var result = temporal.VerifiedChildV2{
        .position = position,
        .kind = kind,
        .scope = .complete_execution,
        .proof_present = true,
        .roster_count = temporal.COMPLETE_ROSTER_COUNT,
        .session_id = session_id,
        .job_id = try temporal.jobId(&words),
        .recursive_parent_vk_id = parent_vk_id,
        .verification_key_id = vk_id,
        .air_program_id = labelled(label, "air"),
        .manifest_id = labelled(label, "manifest"),
        .profile_id = labelled(label, "profile"),
        .statement_words = words,
        .proof_id = labelled(label, "proof"),
        .transcript_id = labelled(label, "transcript"),
        .capture_id = labelled(label, "capture"),
        .verifier_receipt_id = labelled(label, "receipt"),
        .claimed_sums_id = labelled(label, "claims"),
        .relation_replay_id = labelled(label, "replay"),
        .auxiliary_claim_seal_id = labelled(label, "aux"),
        .closure_receipt_id = undefined,
        .lineage_id = labelled(label, "lineage"),
        .closure_value = .{ 0, 0, 0, 0 },
    };
    result.closure_receipt_id = try temporal.closureReceiptId(&result);
    return result;
}

fn emptyChild(
    position: temporal.ChildPosition,
    statement: span.SpanStatement,
    session_id: temporal.Digest,
    parent_vk_id: temporal.Digest,
) !temporal.VerifiedChildV2 {
    const words = try statement.canonicalWords();
    const zero = [_]u32{0} ** channel.RATE;
    return .{
        .position = position,
        .kind = .empty_leaf,
        .scope = .protocol_padding,
        .proof_present = false,
        .roster_count = 0,
        .session_id = session_id,
        .job_id = try temporal.jobId(&words),
        .recursive_parent_vk_id = parent_vk_id,
        .verification_key_id = zero,
        .air_program_id = zero,
        .manifest_id = zero,
        .profile_id = zero,
        .statement_words = words,
        .proof_id = zero,
        .transcript_id = zero,
        .capture_id = zero,
        .verifier_receipt_id = zero,
        .claimed_sums_id = zero,
        .relation_replay_id = zero,
        .auxiliary_claim_seal_id = zero,
        .closure_receipt_id = zero,
        .lineage_id = zero,
        .closure_value = .{ 0, 0, 0, 0 },
    };
}

fn machineState(pc: u32, label: []const u8) !span.MachineState {
    return span.MachineState.init(
        pc,
        .{0} ** 32,
        id(label),
        .{0} ** 8,
    );
}

fn statementId(words: *const span.StatementWords) temporal.Digest {
    var canonical: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return protocol.statementId(&canonical);
}

fn id(label: []const u8) temporal.Digest {
    return channel.hashBytes(label, 0x5450_5453); // "TPTS"
}

fn labelled(left: []const u8, right: []const u8) temporal.Digest {
    var buffer: [64]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ left, right }) catch
        unreachable;
    return id(rendered);
}
