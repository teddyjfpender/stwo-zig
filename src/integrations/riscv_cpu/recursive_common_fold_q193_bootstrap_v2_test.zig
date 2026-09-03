const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_common_fold_q193_bootstrap_v2.zig");
const geometry_support =
    @import("recursive_common_fold_q193_bootstrap_geometry_v2.zig");
const canonical_proof =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const canonical_input =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const fold_input = @import("recursive_common_fold_input_v2.zig");
const throughput =
    @import("recursive_recursion_verifier_throughput_v1.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const node_v1 = @import("recursive_node_artifact_v1.zig");
const node_v2 = @import("recursive_node_artifact_v2.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const recursion = frontend.recursion;
const span = recursion.span_statement;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

test "nonproduction common-fold q193 bootstrap preserves canonical child artifact ownership" {
    comptime {
        if (!@hasDecl(
            subject.Fixed.BoundaryV2,
            "validateAuthenticatedChildOnlyWireBoundary",
        ) or !@hasDecl(
            subject.Fixed.OwnerV2,
            "validateEngineCompositionAuthority",
        ) or !@hasDecl(
            subject.Kernel,
            "reconstructVerifiedReplayWithCohort",
        ) or !@hasDecl(
            subject.Kernel,
            "verifyColdWithReplay",
        )) @compileError(
            "common-fold engine lacks retained prepared replay authority",
        );
        if (!subject.Kernel.VERIFIER_REPLAY_SHARING_AVAILABLE or
            subject.Kernel.SERIALIZABLE_VERIFIER_REPLAY_AUTHORITY or
            @hasDecl(subject.Kernel.VerifiedColdReplayV1, "encode") or
            @hasDecl(subject.Kernel.VerifiedColdReplayV1, "decode"))
        {
            @compileError("common-fold verifier replay authority drifted");
        }
    }
    const allocator = std.testing.allocator;
    var left_fixture = try Fixture.init(210);
    var right_fixture = try Fixture.init(211);
    const left_source = try canonical_input.SourceArtifactV1.seal(
        &left_fixture.leaf,
    );
    const right_source = try canonical_input.SourceArtifactV1.seal(
        &right_fixture.leaf,
    );
    const left_source_bytes = try left_source.encodeCanonical();
    const right_source_bytes = try right_source.encodeCanonical();

    var left_proved = try marked(
        "left.prove",
        canonical_proof.proveAndColdVerify(
            allocator,
            &left_source_bytes,
            .{ .worker_count = 1 },
        ),
    );
    const left_artifact = try marked(
        "left.encode",
        left_proved.proof.encodeArtifactAlloc(allocator),
    );
    defer allocator.free(left_artifact);
    left_proved.deinit();
    var left_cold = try marked(
        "left.cold-open",
        canonical_proof.coldOpen(
            allocator,
            &left_source_bytes,
            left_artifact,
        ),
    );

    var right_proved = try marked(
        "right.prove",
        canonical_proof.proveAndColdVerify(
            allocator,
            &right_source_bytes,
            .{ .worker_count = 1 },
        ),
    );
    const right_artifact = try marked(
        "right.encode",
        right_proved.proof.encodeArtifactAlloc(allocator),
    );
    defer allocator.free(right_artifact);
    right_proved.deinit();
    var right_cold = try marked(
        "right.cold-open",
        canonical_proof.coldOpen(
            allocator,
            &right_source_bytes,
            right_artifact,
        ),
    );

    const registry = try marked(
        "bootstrap.registry",
        subject.bootstrapRegistry(&left_cold, &right_cold),
    );
    const campaign_namespace_sha256 = shaBytes(73);
    var left_lease = try marked(
        "left.lease",
        subject.CanonicalChildLeaseV2.initOwned(
            left_cold,
            registry,
            campaign_namespace_sha256,
        ),
    );
    left_cold = undefined;
    defer left_lease.deinit();
    var right_lease = try marked(
        "right.lease",
        subject.CanonicalChildLeaseV2.initOwned(
            right_cold,
            registry,
            campaign_namespace_sha256,
        ),
    );
    right_cold = undefined;
    defer right_lease.deinit();

    const left_child = try marked(
        "left.fold-child",
        left_lease.requireFoldChild(&registry),
    );
    const right_child = try marked(
        "right.fold-child",
        right_lease.requireFoldChild(&registry),
    );
    try std.testing.expect(
        left_child.ingress.node_public ==
            &left_child.wrapper.artifact.node_public,
    );
    try std.testing.expect(
        right_child.ingress.node_public ==
            &right_child.wrapper.artifact.node_public,
    );
    try std.testing.expectEqualDeep(
        left_lease.admission.evidence.cold.node_public,
        left_child.ingress.node_public.*,
    );
    try std.testing.expectEqualDeep(
        right_lease.admission.evidence.cold.node_public,
        right_child.ingress.node_public.*,
    );
    const input = try marked(
        "fold.input",
        fold_input.FreshFoldInputV2.init(
            left_child.wrapper,
            right_child.wrapper,
            try node_v2.TaskCoordinateV1.init(1, 105),
            &registry,
        ),
    );
    const live = try marked(
        "fold.live",
        subject.BootstrapLiveV2.init(
            &input,
            .{ &left_child, &right_child },
            &registry,
        ),
    );

    var fold_prove_timer = try std.time.Timer.start();
    var proved = try marked(
        "fold.prove-cold-verify",
        subject.proveAndColdVerify(
            allocator,
            &live,
            .{ .worker_count = 1 },
        ),
    );
    const fold_prove_total_ns = fold_prove_timer.read();
    try marked("fold.validate", proved.validate());
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.REGISTRY_PARITY_MINTED);
    try std.testing.expect(!subject.REAL_LEAF_ROLE_AVAILABLE);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    const node_ref = try proved.node_artifact.artifactRef();
    try std.testing.expectEqual(node_v2.RECURSIVE_NODE_ARTIFACT_KIND, node_ref.kind);
    try std.testing.expectEqual(node_v2.SCHEMA_VERSION, node_ref.schema_version);
    try std.testing.expectEqual(
        @as(u16, 193),
        proved.geometry_value.proof_shape.query_count,
    );
    var maximum_active_log: u8 = 0;
    for (proved.geometry_value.active_component_log_sizes[0..proved.geometry_value.component_count]) |log_size|
        maximum_active_log = @max(maximum_active_log, log_size);
    try std.testing.expectEqual(
        maximum_active_log,
        proved.geometry_value.trace_log_size,
    );
    try std.testing.expect(
        @as(usize, maximum_active_log) >
            subject.DIMENSIONS.maximum_merkle_depth - 1,
    );
    var stale_trace_geometry = proved.geometry_value;
    stale_trace_geometry.trace_log_size -= 1;
    stale_trace_geometry.authority_identity_sha256 = undefined;
    try std.testing.expectError(
        error.InvalidCircuitGeometry,
        @TypeOf(stale_trace_geometry).seal(stale_trace_geometry),
    );
    {
        var geometry_cohort = try subject.SecureCohort.init(
            allocator,
            .{ .live = &live },
        );
        defer geometry_cohort.deinit();
        try geometry_support.validateCaptureDerivedCommonShape(
            geometry_cohort.manifest(),
            &proved.fresh,
            &proved.geometry_value.proof_shape,
        );
        try std.testing.expectError(
            error.BootstrapDimensionMismatch,
            geometry_support.requireExactFixedShape(
                &proved.geometry_value.proof_shape,
            ),
        );
        var shape_mutation = proved.geometry_value.proof_shape;
        shape_mutation.maximum_merkle_depth -= 1;
        try std.testing.expectError(
            error.BootstrapCommonGeometryMismatch,
            geometry_support.validateCaptureDerivedCommonShape(
                geometry_cohort.manifest(),
                &proved.fresh,
                &shape_mutation,
            ),
        );
    }
    try std.testing.expect(!std.mem.eql(
        u8,
        &proved.node_artifact.registry_identity_sha256,
        &registry.identity_sha256,
    ));

    const first_remint = try marked("fold.remint", proved.requireRemint());
    try std.testing.expectEqual(@as(usize, 193), first_remint.query_words.len);
    try std.testing.expect(
        first_remint.query_words == &proved.query_authority.query_words,
    );
    try std.testing.expect(
        first_remint.graph.query_words == &proved.query_authority.query_words,
    );
    const first_geometry = proved.geometry_value;
    const first_query_identity = proved.query_authority.query_words_identity_sha256;
    const proof_bytes = try allocator.dupe(u8, proved.proofBytes());
    defer allocator.free(proof_bytes);
    const node_bytes = try proved.node_artifact.encodeCanonical();
    proved.deinit();

    var fold_cold_timer = try std.time.Timer.start();
    var cold = try marked(
        "fold.destroy-cold-open",
        subject.coldOpen(allocator, &live, proof_bytes, &node_bytes),
    );
    const fold_cold_total_ns = fold_cold_timer.read();
    defer cold.deinit();
    try marked("fold.cold-validate", cold.validate());
    try requireMarked(
        "fold.cold-proof-bytes",
        std.mem.eql(u8, proof_bytes, cold.proofBytes()),
        error.CommonFoldSharedReplayProofBytesChanged,
    );
    const reopened_node_bytes = try cold.node_artifact.encodeCanonical();
    try requireMarked(
        "fold.cold-node-bytes",
        std.mem.eql(u8, &node_bytes, &reopened_node_bytes),
        error.CommonFoldSharedReplayNodeBytesChanged,
    );
    const cold_boundary = cold.performanceSnapshot();
    try requireMarked(
        "fold.cold-counters.q193",
        cold_boundary.q193_cold_verifications == 1,
        error.CommonFoldColdQ193CountMismatch,
    );
    try requireMarked(
        "fold.cold-counters.replay",
        cold_boundary.transcript_replays == 1,
        error.CommonFoldColdReplayCountMismatch,
    );
    try requireMarked(
        "fold.cold-counters.graph",
        cold_boundary.graph_records == 1,
        error.CommonFoldColdGraphCountMismatch,
    );
    const preprocessed_cache = subject.Kernel.preprocessedCacheSnapshot();
    try requireMarked(
        "fold.cold-cache.dynamic-manifest-supported",
        subject.Kernel.processLocalPreprocessedCacheAvailable(),
        error.CommonFoldDynamicPreprocessedCacheUnavailable,
    );
    try requireMarked(
        "fold.cold-cache.accounting",
        preprocessed_cache.lookups ==
            preprocessed_cache.hits + preprocessed_cache.misses,
        error.CommonFoldPreprocessedCacheAccountingMismatch,
    );
    try requireMarked(
        "fold.cold-cache.miss-reference",
        preprocessed_cache.lookups == 3 and
            preprocessed_cache.hits == 2 and
            preprocessed_cache.misses == 1 and
            preprocessed_cache.full_rebuilds == 1 and
            preprocessed_cache.rejections == 0 and
            preprocessed_cache.evictions == 0,
        error.CommonFoldPreprocessedCacheLifecycleMismatch,
    );
    var cache_cohort = try marked(
        "fold.cold-cache.cohort",
        subject.SecureCohort.init(allocator, .{ .live = &live }),
    );
    defer cache_cohort.deinit();
    const cache_key = try marked(
        "fold.cold-cache.key",
        cache_cohort.processLocalPreprocessedCacheKey(
            cold.session.protocol.identity_sha256,
            cold.geometry_value.preprocessed_root,
        ),
    );
    try cache_key.validate();
    const original_manifest_seal = cache_cohort.manifest_value.seal;
    cache_cohort.manifest_value.seal[0] ^= 1;
    try marked(
        "fold.cold-cache.manifest-mutation",
        std.testing.expectError(
            error.BootstrapManifestMismatch,
            cache_cohort.processLocalPreprocessedCacheKey(
                cold.session.protocol.identity_sha256,
                cold.geometry_value.preprocessed_root,
            ),
        ),
    );
    cache_cohort.manifest_value.seal = original_manifest_seal;
    try cache_cohort.validate();
    var changed_root = cold.geometry_value.preprocessed_root;
    changed_root[0] ^= 1;
    const changed_root_key = try cache_cohort.processLocalPreprocessedCacheKey(
        cold.session.protocol.identity_sha256,
        changed_root,
    );
    try requireMarked(
        "fold.cold-cache.root-domain",
        !std.meta.eql(cache_key, changed_root_key),
        error.CommonFoldPreprocessedRootCacheCollision,
    );
    var stale_layout_key = cache_key;
    stale_layout_key.padding_identity_sha256[0] ^= 1;
    try marked(
        "fold.cold-cache.layout-mutation",
        std.testing.expectError(
            error.InvalidProcessLocalPreprocessedAuthority,
            stale_layout_key.validate(),
        ),
    );
    var stale_root_key = changed_root_key;
    stale_root_key.identity_sha256 = cache_key.identity_sha256;
    try marked(
        "fold.cold-cache.collision-mutation",
        std.testing.expectError(
            error.InvalidProcessLocalPreprocessedAuthority,
            stale_root_key.validate(),
        ),
    );
    var baseline_timer = try std.time.Timer.start();
    for (0..8) |_| try marked(
        "fold.reuse-baseline-full-audit",
        cold.fullAudit(),
    );
    const baseline_ns = baseline_timer.read();
    const reuse_before = cold.performanceSnapshot();
    var optimized_timer = try std.time.Timer.start();
    for (0..8) |_| _ = try marked(
        "fold.reuse-optimized-remint",
        cold.requireRemint(),
    );
    const optimized_ns = optimized_timer.read();
    const reuse_after = cold.performanceSnapshot();
    try requireMarked(
        "fold.reuse-counters.q193",
        reuse_before.q193_cold_verifications ==
            reuse_after.q193_cold_verifications,
        error.CommonFoldReuseRepeatedQ193,
    );
    try requireMarked(
        "fold.reuse-counters.replay",
        reuse_before.transcript_replays == reuse_after.transcript_replays,
        error.CommonFoldReuseRepeatedReplay,
    );
    try requireMarked(
        "fold.reuse-counters.graph",
        reuse_before.graph_records == reuse_after.graph_records,
        error.CommonFoldReuseRepeatedGraphRecord,
    );
    try requireMarked(
        "fold.reuse-counters.graph-borrows",
        reuse_before.graph_view_borrows + 8 ==
            reuse_after.graph_view_borrows,
        error.CommonFoldReuseGraphBorrowCountMismatch,
    );
    const reuse_receipt = try marked(
        "fold.reuse-receipt.init",
        throughput.ReuseReceiptV1.init(
            cold.validation,
            reuse_before,
            reuse_after,
            8,
            baseline_ns,
            optimized_ns,
        ),
    );
    try marked(
        "fold.reuse-receipt.validate",
        reuse_receipt.validateAgainst(cold.validation),
    );
    const cold_node_ref = try cold.node_artifact.artifactRef();
    const node_sha_hex = std.fmt.bytesToHex(cold_node_ref.sha256, .lower);
    const proof_sha_hex = std.fmt.bytesToHex(
        cold.node_artifact.proof_ref.sha256,
        .lower,
    );
    const capture_sha_hex = std.fmt.bytesToHex(
        cold.composition_capture.identity_sha256,
        .lower,
    );
    if (!reuse_receipt.meetsStretchTarget() or
        std.process.hasEnvVarConstant("STWO_RECURSION_BENCH")) std.debug.print(
        "COMMON_FOLD_REUSE_AB node_sha={s} proof_sha={s} capture_sha={s} preprocessed_root={any} prove_total_ns={d} cold_open_total_ns={d} baseline_ns={d} optimized_ns={d} reduction_bps={d} q193_ns={d} replay_ns={d} graph_ns={d} cache_hits={d} cache_misses={d} cache_lookup_ns={d} cache_rebuild_ns={d}\n",
        .{
            &node_sha_hex,
            &proof_sha_hex,
            &capture_sha_hex,
            cold.geometry_value.preprocessed_root,
            fold_prove_total_ns,
            fold_cold_total_ns,
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
    try std.testing.expectEqualDeep(first_geometry, cold.geometry_value);
    try std.testing.expectEqualDeep(
        first_query_identity,
        cold.query_authority.query_words_identity_sha256,
    );
    const cold_remint = try marked("fold.cold-remint", cold.requireRemint());
    try cold_remint.validateBorrowed();
    try std.testing.expect(
        cold_remint.query_words == &cold.query_authority.query_words,
    );
    try std.testing.expect(
        cold_remint.graph.query_words == &cold.query_authority.query_words,
    );
    const original_graph_value = cold.composition_capture.node_values[0];
    cold.composition_capture.node_values[0] = original_graph_value.add(
        QM31.one(),
    );
    try std.testing.expectError(
        error.InvalidCommonFoldCompositionCapture,
        cold.fullAudit(),
    );
    cold.composition_capture.node_values[0] = original_graph_value;
    try cold.validate();
    {
        const original_values = cold.composition_capture.node_values;
        const replacement = try allocator.dupe(QM31, original_values);
        defer allocator.free(replacement);
        cold.composition_capture.node_values = replacement;
        defer cold.composition_capture.node_values = original_values;
        try std.testing.expectError(
            error.InvalidCommonFoldCompositionCapture,
            cold.validate(),
        );
    }
    const original_capture_identity =
        cold.composition_capture.identity_sha256;
    cold.composition_capture.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCommonFoldCompositionCapture,
        cold.validate(),
    );
    cold.composition_capture.identity_sha256 = original_capture_identity;
    const original_capture_word = cold.fresh.statement.capture_id[0];
    cold.fresh.statement.capture_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProcessLocalValidationToken,
        cold.validate(),
    );
    cold.fresh.statement.capture_id[0] = original_capture_word;
    try cold.validate();
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
            cold.validate(),
        );
    }

    var corrupted_node = node_bytes;
    corrupted_node[corrupted_node.len - 1] ^= 1;
    try marked(
        "fold.node-mutation",
        std.testing.expectError(
            error.InvalidArtifactIdentity,
            subject.coldOpen(
                allocator,
                &live,
                proof_bytes,
                &corrupted_node,
            ),
        ),
    );

    const original_query = cold.query_authority.query_words[0];
    cold.query_authority.query_words[0] = original_query.add(M31.one());
    // Cheap process-local validation must reject query/frame mutation through
    // the token that seals the complete query authority. The replay-specific
    // query error belongs to `fullAudit`, which deliberately does more work.
    try marked(
        "fold.query-mutation",
        std.testing.expectError(
            error.InvalidProcessLocalValidationToken,
            cold.validate(),
        ),
    );
    cold.query_authority.query_words[0] = original_query;
    const original_draw_count = cold.query_authority.final_transcript_draw_count;
    cold.query_authority.final_transcript_draw_count +%= 1;
    try marked(
        "fold.query-frame-mutation",
        std.testing.expectError(
            error.InvalidProcessLocalValidationToken,
            cold.validate(),
        ),
    );
    cold.query_authority.final_transcript_draw_count = original_draw_count;
    try cold.validate();
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
        node_v1.REAL_LEAF_COUNT,
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
            "COMMON_FOLD_Q193_BOOTSTRAP_STAGE={s} error={s}\n",
            .{ stage, @errorName(err) },
        );
        return err;
    };
}

fn requireMarked(
    comptime stage: []const u8,
    condition: bool,
    failure: anyerror,
) !void {
    if (condition) return;
    std.debug.print(
        "COMMON_FOLD_Q193_BOOTSTRAP_STAGE={s} error={s}\n",
        .{ stage, @errorName(failure) },
    );
    return failure;
}
