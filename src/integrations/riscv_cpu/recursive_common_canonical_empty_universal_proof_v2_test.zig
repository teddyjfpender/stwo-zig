const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const input_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
const cohort_mod =
    @import("recursive_common_canonical_empty_universal_cohort_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const preprocessed_authority =
    @import("recursive_process_local_preprocessed_authority_v1.zig");
const throughput =
    @import("recursive_recursion_verifier_throughput_v1.zig");
const artifact_mod = @import("recursive_node_artifact_v1.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const recursion = frontend.recursion;
const span = recursion.span_statement;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

test "canonical-empty universal source selects exact q193 cohort" {
    var fixture = try Fixture.init(210);
    const source = try input_mod.SourceArtifactV1.seal(&fixture.leaf);
    const bytes = try source.encodeCanonical();
    const cold = try input_mod.ColdInputV1.open(&bytes);

    var cohort = try @import(
        "recursive_common_canonical_empty_universal_cohort_v2.zig",
    ).CohortV2.init(std.testing.allocator, .{
        .statement_words = cold.source.statement_words,
        .coordinate = try cold.coordinate(),
    });
    defer cohort.deinit();
    try cohort.validate();
    const manifest = cohort.manifest();
    try manifest_mod.validateExact(manifest);
    const session = try cohort.session();
    try session.protocol.requireSecure();
    try cohort.validateSession(&session);
    try std.testing.expectEqual(@as(u32, 193), session.protocol.fri_query_count);
    try std.testing.expectEqual(@as(u32, 4), session.protocol.fri_fold_step);
    try std.testing.expectEqual(@as(u32, 16), session.protocol.pcs_pow_bits);
    try std.testing.expectEqual(@as(usize, 113), cohort.schedule.calls.len);
    try std.testing.expectEqual(@as(u32, 570), manifest.total_preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 1044), manifest.total_main_columns);
    try std.testing.expectEqual(@as(u32, 560), manifest.total_interaction_columns);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.REGISTRY_PARITY_AVAILABLE);
}

test "VerifiedReplay separates statement audit from cohort custody identity" {
    var replay: subject.Kernel.VerifiedReplay = undefined;
    replay.claims = std.mem.zeroes(manifest_mod.ClaimVector);
    replay.claims.seal = shaBytes(31);
    replay.audited = std.mem.zeroes(cohort_mod.AuditedInteractionsV2);
    replay.audited.closure.closure_id = shaBytes(47);
    replay.audited.wire_boundary.tuple_count = 113;
    replay.transcript_audit_sha256 =
        replay.computedTranscriptAuditIdentity();
    replay.audited.identity_sha256 = replay.transcript_audit_sha256;
    replay.audited.identity_sha256[0] ^= 1;

    try replay.validateStatementAudit(replay.transcript_audit_sha256);
    try std.testing.expect(!std.mem.eql(
        u8,
        &replay.transcript_audit_sha256,
        &replay.audited.identity_sha256,
    ));

    const statement_audit = replay.transcript_audit_sha256;
    replay.transcript_audit_sha256[1] ^= 1;
    try std.testing.expectError(
        error.SecureTemporalParentStatementMismatch,
        replay.validateStatementAudit(statement_audit),
    );
}

test "canonical-empty q193 proof survives retained cold reopen and rejects mutation" {
    const allocator = std.testing.allocator;
    try exercisePreprocessedAuthorityHostility();
    var fixture = try Fixture.init(211);
    const source = try marked(
        "test.source-build",
        input_mod.SourceArtifactV1.seal(&fixture.leaf),
    );
    const source_bytes = try marked(
        "test.source-encode",
        source.encodeCanonical(),
    );

    var proved = try marked(
        "test.prove-cold-capture",
        subject.proveAndColdVerify(
            allocator,
            &source_bytes,
            .{ .worker_count = 1 },
        ),
    );
    try marked("test.receipt", proved.receipt.validate());
    const prove_receipt = proved.receipt;
    const retained = try marked(
        "test.artifact-encode",
        proved.proof.encodeArtifactAlloc(allocator),
    );
    defer allocator.free(retained);
    const first_statement = proved.proof.fresh.statement;
    const first_shape = proved.proof.geometry_value.proof_shape;
    try std.testing.expectEqualDeep(
        subject.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
        try subject.fixedWireDimensionsFromColdShape(&first_shape),
    );
    try std.testing.expectEqualSlices(
        u8,
        &subject.CAPTURE_DERIVED_FRI_FOLD_WIDTHS_V2,
        first_shape.fri_layer_fold_widths[0..first_shape.fri_layer_count],
    );
    try std.testing.expectEqualSlices(
        u8,
        &subject.CAPTURE_DERIVED_FRI_PATH_DEPTHS_V2,
        first_shape.fri_layer_path_depths[0..first_shape.fri_layer_count],
    );
    proved.deinit();

    var cold_open_timer = try std.time.Timer.start();
    var cold = try marked(
        "test.destroy-decode-cold-verify",
        subject.coldOpen(allocator, &source_bytes, retained),
    );
    const cold_open_ns = cold_open_timer.read();
    defer cold.deinit();
    const cold_boundary = cold.performanceSnapshot();
    try std.testing.expectEqual(@as(u64, 1), cold_boundary.q193_cold_verifications);
    try std.testing.expectEqual(@as(u64, 1), cold_boundary.transcript_replays);
    try std.testing.expectEqual(@as(u64, 1), cold_boundary.graph_records);
    try std.testing.expectEqual(@as(u64, 0), cold_boundary.full_audits);
    try std.testing.expectEqual(@as(u64, 0), cold_boundary.graph_view_borrows);
    try std.testing.expect(subject.Kernel.processLocalPreprocessedCacheAvailable());
    const preprocessed_cache = subject.Kernel.preprocessedCacheSnapshot();
    try std.testing.expectEqual(@as(u64, 4), preprocessed_cache.lookups);
    try std.testing.expectEqual(@as(u64, 3), preprocessed_cache.hits);
    try std.testing.expectEqual(@as(u64, 1), preprocessed_cache.misses);
    try std.testing.expectEqual(@as(u64, 1), preprocessed_cache.full_rebuilds);
    try std.testing.expectEqual(@as(u64, 0), preprocessed_cache.rejections);
    try std.testing.expectEqual(@as(u64, 0), preprocessed_cache.evictions);
    var baseline_timer = try std.time.Timer.start();
    for (0..8) |_| try cold.validate();
    const baseline_ns = baseline_timer.read();
    const reuse_before = cold.performanceSnapshot();
    var optimized_timer = try std.time.Timer.start();
    for (0..8) |_| {
        _ = try cold.ingressView();
        _ = try cold.foldGraphView();
    }
    const optimized_ns = optimized_timer.read();
    const reused = cold.performanceSnapshot();
    try std.testing.expectEqual(
        cold_boundary.q193_cold_verifications,
        reused.q193_cold_verifications,
    );
    try std.testing.expectEqual(
        cold_boundary.transcript_replays + 8,
        reused.transcript_replays,
    );
    try std.testing.expectEqual(
        cold_boundary.graph_records,
        reused.graph_records,
    );
    try std.testing.expectEqual(@as(u64, 8), reused.full_audits);
    try std.testing.expectEqual(@as(u64, 8), reused.graph_view_borrows);
    const reuse_receipt = try throughput.ReuseReceiptV1.init(
        cold.validation,
        reuse_before,
        reused,
        8,
        baseline_ns,
        optimized_ns,
    );
    try reuse_receipt.validateAgainst(cold.validation);
    const cold_proof_ref = try cold.proofArtifactRef();
    const proof_sha_hex = std.fmt.bytesToHex(cold_proof_ref.sha256, .lower);
    const capture_sha_hex = std.fmt.bytesToHex(
        cold.composition_capture.identity_sha256,
        .lower,
    );
    if (!reuse_receipt.meetsStretchTarget() or
        std.process.hasEnvVarConstant("STWO_RECURSION_BENCH")) std.debug.print(
        "CANONICAL_EMPTY_REUSE_AB proof_sha={s} capture_sha={s} preprocessed_root={any} prove_ns={d} prove_fresh_verify_ns={d} cold_open_total_ns={d} baseline_ns={d} optimized_ns={d} reduction_bps={d} q193_ns={d} replay_ns={d} graph_ns={d} cache_hits={d} cache_misses={d} cache_lookup_ns={d} cache_rebuild_ns={d}\n",
        .{
            &proof_sha_hex,
            &capture_sha_hex,
            cold.geometry_value.preprocessed_root,
            prove_receipt.prove_ns,
            prove_receipt.cold_verify_ns,
            cold_open_ns,
            baseline_ns,
            optimized_ns,
            reuse_receipt.measured_reduction_bps,
            cold_boundary.q193_cold_verification_ns,
            cold_boundary.transcript_replay_ns,
            cold_boundary.graph_record_ns,
            preprocessed_cache.hits,
            preprocessed_cache.misses,
            preprocessed_cache.lookup_ns,
            preprocessed_cache.rebuild_ns,
        },
    );
    try std.testing.expect(reuse_receipt.meetsStretchTarget());
    try std.testing.expectEqualDeep(first_statement, cold.fresh.statement);
    try std.testing.expectEqualDeep(first_shape, cold.geometry_value.proof_shape);
    try std.testing.expectEqual(@as(u16, 36), first_shape.claimed_sum_count);
    try std.testing.expectEqual(@as(u16, 570), first_shape.tree_column_counts[0]);
    try std.testing.expectEqual(@as(u16, 1044), first_shape.tree_column_counts[1]);
    try std.testing.expectEqual(@as(u16, 560), first_shape.tree_column_counts[2]);
    try std.testing.expectEqual(@as(u16, 193), first_shape.query_count);
    try std.testing.expect(first_shape.sampled_value_count > 0);
    try std.testing.expect(first_shape.fri_layer_count > 0);
    for (
        first_shape.fri_layer_fold_widths[0..first_shape.fri_layer_count],
        first_shape.fri_layer_path_depths[0..first_shape.fri_layer_count],
    ) |width, depth| {
        try std.testing.expect(width > 0);
        try std.testing.expect(depth > 0);
    }
    const ingress = try marked("test.ingress", cold.ingressView());
    try marked("test.ingress-validate", ingress.validate());
    const graph = try marked("test.fold-graph", cold.foldGraphView());
    try marked("test.fold-graph-seal", graph.lane.graph.validate());
    try std.testing.expectEqual(
        graph.lane.graph.nodes.len,
        graph.evaluation.values.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        &graph.lane.graph.identity_digest,
        &graph.evaluation.circuit_identity,
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        graph.capture_identity_sha256,
        0,
    ));
    try std.testing.expectEqual(
        cold.fresh.statement.interaction_pow_nonce,
        ingress.statement.interaction_pow_nonce,
    );
    try std.testing.expectEqualDeep(cold.claims, ingress.claims.*);
    try std.testing.expect(graph.query_words == &cold.query_authority.query_words);
    try std.testing.expect(ingress.query_words == &cold.query_authority.query_words);
    try std.testing.expectEqual(@as(usize, 193), graph.query_words.len);
    try std.testing.expectEqual(
        cold.query_authority.final_transcript_draw_count,
        graph.final_transcript_draw_count,
    );
    try std.testing.expectEqualDeep(
        cold.fresh.statement.transcript_id,
        recursion.protocol.transcriptId(
            graph.final_transcript_digest.*,
            graph.final_transcript_draw_count,
        ),
    );

    const original_query = cold.query_authority.query_words[0];
    cold.query_authority.query_words[0] = original_query.add(M31.one());
    try std.testing.expectError(
        error.InvalidProcessLocalValidationToken,
        cold.validateToken(),
    );
    try marked(
        "test.query-word-mutation",
        std.testing.expectError(
            error.InvalidCanonicalEmptyQueryAuthority,
            cold.validate(),
        ),
    );
    cold.query_authority.query_words[0] = original_query;
    const original_draw_count = cold.query_authority.final_transcript_draw_count;
    cold.query_authority.final_transcript_draw_count +%= 1;
    try std.testing.expectError(
        error.InvalidProcessLocalValidationToken,
        cold.validateToken(),
    );
    try marked(
        "test.query-frame-mutation",
        std.testing.expectError(
            error.InvalidCanonicalEmptyQueryAuthority,
            cold.validate(),
        ),
    );
    cold.query_authority.final_transcript_draw_count = original_draw_count;
    try cold.validate();

    const original_capture_word = cold.fresh.statement.capture_id[0];
    cold.fresh.statement.capture_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProcessLocalValidationToken,
        cold.validateToken(),
    );
    cold.fresh.statement.capture_id[0] = original_capture_word;
    try cold.validateToken();

    const original_claim = cold.claims.values[0];
    cold.claims.values[0] = original_claim.add(QM31.one());
    try marked(
        "test.claim-mutation",
        std.testing.expectError(
            error.CanonicalEmptyUniversalProofMismatch,
            cold.validate(),
        ),
    );
    cold.claims.values[0] = original_claim;
    try cold.validate();

    const original_node = cold.composition_capture.node_values[0];
    cold.composition_capture.node_values[0] = original_node.add(QM31.one());
    try marked(
        "test.graph-mutation",
        std.testing.expectError(
            error.InvalidCanonicalEmptyCompositionCapture,
            cold.validate(),
        ),
    );
    cold.composition_capture.node_values[0] = original_node;
    _ = try marked("test.graph-restored", cold.foldGraphView());

    {
        const original_values = cold.composition_capture.node_values;
        const replacement = try allocator.dupe(QM31, original_values);
        defer allocator.free(replacement);
        cold.composition_capture.node_values = replacement;
        defer cold.composition_capture.node_values = original_values;
        try std.testing.expectError(
            error.InvalidCanonicalEmptyCompositionCapture,
            cold.validateToken(),
        );
    }
    {
        const original_validation = cold.validation;
        const replacement = try allocator.create(
            process_validation.ValidatedOwnerV1,
        );
        defer allocator.destroy(replacement);
        replacement.* = try process_validation.ValidatedOwnerV1.init(
            original_validation.token.snapshot,
        );
        cold.validation = replacement;
        defer cold.validation = original_validation;
        try std.testing.expectError(
            error.InvalidProcessLocalValidationToken,
            cold.validateToken(),
        );
    }
    const original_graph_identity =
        cold.composition_capture.identity_sha256;
    cold.composition_capture.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptyCompositionCapture,
        cold.validateToken(),
    );
    cold.composition_capture.identity_sha256 = original_graph_identity;
    try cold.validateToken();

    const inputs = blk: {
        const opened = try input_mod.ColdInputV1.open(&source_bytes);
        break :blk @import(
            "recursive_common_canonical_empty_universal_cohort_v2.zig",
        ).AuthorityInputs{
            .statement_words = opened.source.statement_words,
            .coordinate = try opened.coordinate(),
        };
    };
    var replay_cohort = try @import(
        "recursive_common_canonical_empty_universal_cohort_v2.zig",
    ).CohortV2.init(allocator, inputs);
    defer replay_cohort.deinit();
    var replay = try subject.Kernel.reconstructVerifiedReplay(
        allocator,
        inputs,
        &cold.session,
        &cold.fresh,
    );
    try marked("test.replay-validate", replay.validateAgainst(&replay_cohort));
    replay.claims.values[0] = replay.claims.values[0].add(QM31.one());
    try marked(
        "test.replay-mutation",
        std.testing.expectError(
            error.SecureTemporalParentStatementMismatch,
            replay.validateAgainst(&replay_cohort),
        ),
    );

    cold.fresh.capture.commitments[0][0] ^= 1;
    try marked(
        "test.capture-root-mutation",
        std.testing.expectError(
            error.SecureTemporalParentStatementMismatch,
            cold.validate(),
        ),
    );
    cold.fresh.capture.commitments[0][0] ^= 1;
    try cold.validate();

    var corrupted = try allocator.dupe(u8, retained);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try marked(
        "test.artifact-mutation",
        std.testing.expectError(
            error.InvalidSecureTemporalParentArtifact,
            subject.coldOpen(allocator, &source_bytes, corrupted),
        ),
    );
}

fn exercisePreprocessedAuthorityHostility() !void {
    const Root = [8]u32;
    const Cache = preprocessed_authority.CacheV1(Root);
    const root = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const layout = shaBytes(17);
    const manifest = shaBytes(19);
    const key = try preprocessed_authority.KeyV1.init(.{
        .circuit_identity_sha256 = shaBytes(21),
        .program_identity_sha256 = shaBytes(23),
        .profile_identity_sha256 = shaBytes(25),
        .pcs_identity_sha256 = shaBytes(27),
        .padding_identity_sha256 = shaBytes(29),
        .preprocessed_identity_sha256 = try preprocessed_authority.preprocessedIdentity(
            Root,
            layout,
            manifest,
            root,
        ),
        .identity_sha256 = undefined,
    });
    const Authority = preprocessed_authority.AuthorityV1(Root);
    var authority = try Authority.init(key, root);
    try authority.validateAgainst(&key, root);

    var identity_mutation = key;
    identity_mutation.circuit_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProcessLocalPreprocessedAuthority,
        identity_mutation.validate(),
    );
    var layout_mutation = key;
    layout_mutation.padding_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProcessLocalPreprocessedAuthority,
        layout_mutation.validate(),
    );
    authority.root[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProcessLocalPreprocessedAuthority,
        authority.validateAgainst(&key, root),
    );
    authority.root[0] ^= 1;

    var cache = Cache{};
    try cache.ensure(key, root, true, PreprocessedFixtureBuilder.rebuild);
    try cache.ensure(key, root, true, PreprocessedFixtureBuilder.rebuild);
    var wrong_root = root;
    wrong_root[0] ^= 1;
    const wrong_key = try preprocessed_authority.KeyV1.init(.{
        .circuit_identity_sha256 = key.circuit_identity_sha256,
        .program_identity_sha256 = key.program_identity_sha256,
        .profile_identity_sha256 = key.profile_identity_sha256,
        .pcs_identity_sha256 = key.pcs_identity_sha256,
        .padding_identity_sha256 = key.padding_identity_sha256,
        .preprocessed_identity_sha256 = try preprocessed_authority.preprocessedIdentity(
            Root,
            layout,
            manifest,
            wrong_root,
        ),
        .identity_sha256 = undefined,
    });
    try std.testing.expectError(
        error.RejectedPreprocessedFixture,
        cache.ensure(
            wrong_key,
            wrong_root,
            false,
            PreprocessedFixtureBuilder.rebuild,
        ),
    );
    var wrong_layout = layout;
    wrong_layout[0] ^= 1;
    const wrong_layout_key = try preprocessed_authority.KeyV1.init(.{
        .circuit_identity_sha256 = key.circuit_identity_sha256,
        .program_identity_sha256 = key.program_identity_sha256,
        .profile_identity_sha256 = key.profile_identity_sha256,
        .pcs_identity_sha256 = key.pcs_identity_sha256,
        .padding_identity_sha256 = key.padding_identity_sha256,
        .preprocessed_identity_sha256 = try preprocessed_authority.preprocessedIdentity(
            Root,
            wrong_layout,
            manifest,
            root,
        ),
        .identity_sha256 = undefined,
    });
    try std.testing.expectError(
        error.RejectedPreprocessedFixture,
        cache.ensure(
            wrong_layout_key,
            root,
            false,
            PreprocessedFixtureBuilder.rebuild,
        ),
    );
    // Neither rejected candidate may evict or replace the first authenticated
    // authority; reopening the original key remains a cache hit.
    try cache.ensure(key, root, true, PreprocessedFixtureBuilder.rebuild);
    const counters = cache.snapshot();
    try std.testing.expectEqual(@as(u64, 5), counters.lookups);
    try std.testing.expectEqual(@as(u64, 2), counters.hits);
    try std.testing.expectEqual(@as(u64, 3), counters.misses);
    try std.testing.expectEqual(@as(u64, 1), counters.full_rebuilds);
    try std.testing.expectEqual(@as(u64, 2), counters.rejections);
    try std.testing.expectEqual(@as(u64, 0), counters.evictions);
}

const PreprocessedFixtureBuilder = struct {
    fn rebuild(accept: bool) !void {
        if (!accept) return error.RejectedPreprocessedFixture;
    }
};

test "output-less universal fixture never grants registry admission" {
    try std.testing.expect(!subject.REGISTRY_PARITY_AVAILABLE);
    try std.testing.expect(!registry_mod.PRODUCTION_ACTIVATION);
    try std.testing.expectEqual(
        registry_mod.OutputAbiV1.fieldNodePublicV2(),
        registry_mod.OutputAbiV1.fieldNodePublicV2(),
    );
}

const Fixture = struct {
    job: span.JobContext,
    leaf: leaf_mod.LeafOrEmptyV1,

    fn init(index: u32) !Fixture {
        const job = try fixtureJob();
        var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
        try leaf_mod.admitEmptyInto(
            &leaf,
            job,
            index,
            digest(101),
            digest(111),
            digest(121),
        );
        return .{ .job = job, .leaf = leaf };
    }
};

fn fixtureJob() !span.JobContext {
    var initial_registers = [_]u32{0} ** 32;
    var final_registers = [_]u32{0} ** 32;
    initial_registers[1] = 7;
    final_registers[1] = 9;
    const initial = try span.MachineState.init(
        0x1000,
        initial_registers,
        digest(11),
        digest(21),
    );
    const final = try span.MachineState.init(
        0x2000,
        final_registers,
        digest(31),
        digest(41),
    );
    return span.JobContext.init(
        try span.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            digest(51),
            initial,
            final,
            digest(61),
            digest(71),
            88_000,
        ),
        artifact_mod.REAL_LEAF_COUNT,
    );
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaBytes(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn marked(comptime stage: []const u8, value: anytype) @TypeOf(value) {
    return value catch |err| {
        std.debug.print(
            "CANONICAL_EMPTY_Q193_STAGE={s} error={s}\n",
            .{ stage, @errorName(err) },
        );
        return err;
    };
}
