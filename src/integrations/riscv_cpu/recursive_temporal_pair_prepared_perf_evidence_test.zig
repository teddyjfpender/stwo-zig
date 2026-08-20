//! Executed evidence for the prepared temporal pair used by rows 0--17.
//!
//! This is intentionally an integration test, not a detached frontend
//! microbenchmark: the hot arm calls the single production seam exported by
//! `recursive_temporal_nonfri_source_v2.zig`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const child_authority =
    @import("recursive_segment_v2_temporal_child_authority.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const temporal_source = @import("recursive_temporal_nonfri_source_v2.zig");

const recursion = frontend.recursion;
const protocol = recursion.protocol;
const span = recursion.span_statement;
const temporal = recursion.temporal_pair_node;
const Digest = recursion.poseidon2_channel.Digest;

const HOT_ITERATIONS: usize = 4_096;
const HISTORICAL_V1_STATIC_ESTIMATE: usize =
    recursion.pair_node.AuthenticationPermutationCostV1
        .prior_audit_static_estimate;

const ExecutionReceiptV1 = struct {
    historical_v1_static_estimate: usize,
    temporal_pre_dedup_cold: usize,
    temporal_current_cold: usize,
    historical_validation_hashes: usize,
    historical_validation_permutations: usize,
    one_pass_validation_hashes: usize,
    one_pass_validation_permutations: usize,
    real_hot_iterations: usize,
    real_hot_hashes: usize,
    real_hot_permutations: usize,
    historical_hot_snapshot_equality_passes: usize,
    real_hot_snapshot_equality_passes: usize,
    historical_validation_allocations: usize,
    one_pass_validation_allocations: usize,
    hot_allocations: usize,

    fn validate(self: ExecutionReceiptV1) !void {
        if (self.historical_v1_static_estimate != 229 or
            self.temporal_pre_dedup_cold != 499 or
            self.temporal_current_cold != 281 or
            self.historical_validation_hashes !=
                pair_authority.HISTORICAL_VALIDATION_HASH_INVOCATIONS or
            self.historical_validation_permutations !=
                pair_authority.HISTORICAL_VALIDATION_SCALAR_POSEIDON_PERMUTATIONS or
            self.one_pass_validation_hashes !=
                pair_authority.ONE_PASS_VALIDATION_HASH_INVOCATIONS or
            self.one_pass_validation_permutations !=
                pair_authority.ONE_PASS_VALIDATION_SCALAR_POSEIDON_PERMUTATIONS or
            self.real_hot_iterations != HOT_ITERATIONS or
            self.real_hot_hashes != 0 or self.real_hot_permutations != 0 or
            self.historical_hot_snapshot_equality_passes != 3 or
            self.real_hot_snapshot_equality_passes != 0 or
            self.historical_validation_allocations != 0 or
            self.one_pass_validation_allocations != 0 or
            self.hot_allocations != 0)
        {
            return error.InvalidPerformanceReceipt;
        }
    }
};

test "real temporal source uses one-pass validation and zero-hash prepared authentication" {
    const pair = try preparedPairFixture();
    const before = pair;

    var historical_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&historical_audit);
    defer temporal.test_support.cancel(&historical_audit);
    try pair_authority.test_support.validateHistoricalPreOnePass(&pair);
    const historical = try temporal.test_support.finish(&historical_audit);

    var fixed_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&fixed_audit);
    defer temporal.test_support.cancel(&fixed_audit);
    try pair.validate();
    const fixed = try temporal.test_support.finish(&fixed_audit);

    var hot_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&hot_audit);
    defer temporal.test_support.cancel(&hot_audit);
    var checksum: u32 = 0;
    var hot_result: temporal.RootAuthenticatedTemporalPairV2 = undefined;
    for (0..HOT_ITERATIONS) |_| {
        hot_result = try temporal_source.authenticatePreparedPairForSource(
            &pair,
        );
        checksum ^= hot_result.pair.node_id[0];
        std.mem.doNotOptimizeAway(&hot_result);
    }
    std.mem.doNotOptimizeAway(&checksum);
    const hot = try temporal.test_support.finish(&hot_audit);

    var cold_audit = temporal.test_support.PermutationAudit{};
    try temporal.test_support.begin(&cold_audit);
    defer temporal.test_support.cancel(&cold_audit);
    const cold_result = try temporal.authenticateRoot(
        &pair.prepared_root.authority_snapshot,
        &pair.prepared_root.record_snapshot,
        &pair.prepared_root.pin_snapshot,
    );
    const cold = try temporal.test_support.finish(&cold_audit);

    try std.testing.expectEqualDeep(cold_result, hot_result);
    try std.testing.expectEqualDeep(pair.prepared_root.result, hot_result);
    try std.testing.expectEqualDeep(before, pair);
    try std.testing.expectEqual(@as(usize, 13), cold.hash_invocations);
    try std.testing.expectEqual(
        temporal.PreparationPermutationCostV2.successful_complete_pair,
        cold.scalar_poseidon_permutations,
    );

    const receipt = ExecutionReceiptV1{
        .historical_v1_static_estimate = HISTORICAL_V1_STATIC_ESTIMATE,
        .temporal_pre_dedup_cold = temporal.PreparationPermutationCostV2.historical_complete_pair,
        .temporal_current_cold = cold.scalar_poseidon_permutations,
        .historical_validation_hashes = historical.hash_invocations,
        .historical_validation_permutations = historical.scalar_poseidon_permutations,
        .one_pass_validation_hashes = fixed.hash_invocations,
        .one_pass_validation_permutations = fixed.scalar_poseidon_permutations,
        .real_hot_iterations = HOT_ITERATIONS,
        .real_hot_hashes = hot.hash_invocations,
        .real_hot_permutations = hot.scalar_poseidon_permutations,
        .historical_hot_snapshot_equality_passes = pair_authority.HISTORICAL_HOT_SNAPSHOT_EQUALITY_PASSES,
        .real_hot_snapshot_equality_passes = pair_authority.HOT_SNAPSHOT_EQUALITY_PASSES,
        .historical_validation_allocations = pair_authority.HISTORICAL_VALIDATION_HEAP_ALLOCATIONS,
        .one_pass_validation_allocations = pair_authority.ONE_PASS_VALIDATION_HEAP_ALLOCATIONS,
        .hot_allocations = pair_authority.HOT_AUTHENTICATION_HEAP_ALLOCATIONS,
    };
    try receipt.validate();

    // Printed only when the test runner exposes successful-test stderr. The
    // assertions above, rather than this diagnostic line, are the authority.
    std.debug.print(
        "pair_perf_receipt_v1 old_validation_hashes={d} " ++
            "old_validation_permutations={d} one_pass_hashes={d} " ++
            "one_pass_permutations={d} hot_iterations={d} " ++
            "hot_hashes={d} hot_permutations={d} " ++
            "hot_snapshot_equality_passes={d}\n",
        .{
            receipt.historical_validation_hashes,
            receipt.historical_validation_permutations,
            receipt.one_pass_validation_hashes,
            receipt.one_pass_validation_permutations,
            receipt.real_hot_iterations,
            receipt.real_hot_hashes,
            receipt.real_hot_permutations,
            receipt.real_hot_snapshot_equality_passes,
        },
    );
}

const CachedResultMutation = enum {
    format_id,
    protocol_id,
    session_id,
    job_id,
    parent_node_index,
    parent_height,
    child_id,
};

test "one-pass validation rejects cached-result mutations missed by the historical audit" {
    const honest = try preparedPairFixture();
    inline for (std.meta.tags(CachedResultMutation)) |mutation| {
        var changed = honest;
        mutateCachedResult(&changed, mutation);

        // RED evidence: the former independent-snapshot checks accepted these
        // mutations because the returned cache was compared with itself and
        // the outer authority identity did not cover these duplicate fields.
        try pair_authority.test_support.validateHistoricalPreOnePass(&changed);
        try std.testing.expectError(error.PairIdentityMismatch, changed.validate());
    }
}

test "prepared temporal pair optional ABBA wall-time evidence" {
    const encoded_iterations = std.process.getEnvVarOwned(
        std.testing.allocator,
        "STWO_TEMPORAL_PAIR_INTEGRATION_BENCH_ITERATIONS",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer std.testing.allocator.free(encoded_iterations);
    const iterations = try std.fmt.parseInt(usize, encoded_iterations, 10);
    if (iterations < 64 or iterations > 1_000_000)
        return error.InvalidBenchmarkIterations;

    const pair = try preparedPairFixture();
    for (0..16) |_| {
        _ = try runConvenience(&pair, 1);
        _ = try runHistoricalPrepared(&pair, 1);
        _ = try runPrepared(&pair, 1);
    }

    const cold_a = try runConvenience(&pair, iterations);
    const historical_hot_a = try runHistoricalPrepared(&pair, iterations);
    const hot_a = try runPrepared(&pair, iterations);
    const hot_b = try runPrepared(&pair, iterations);
    const historical_hot_b = try runHistoricalPrepared(&pair, iterations);
    const cold_b = try runConvenience(&pair, iterations);
    const cold_total = std.math.add(u64, cold_a, cold_b) catch
        return error.BenchmarkOverflow;
    const hot_total = std.math.add(u64, hot_a, hot_b) catch
        return error.BenchmarkOverflow;
    const historical_hot_total = std.math.add(
        u64,
        historical_hot_a,
        historical_hot_b,
    ) catch return error.BenchmarkOverflow;
    const samples = std.math.mul(usize, iterations, 2) catch
        return error.BenchmarkOverflow;
    const cold_ns_per_op = cold_total / samples;
    const hot_ns_per_op = hot_total / samples;
    const historical_hot_ns_per_op = historical_hot_total / samples;
    std.debug.print(
        "pair_perf_wall_v1 iterations={d} cold_ns_per_op={d} " ++
            "historical_prepared_ns_per_op={d} prepared_ns_per_op={d} " ++
            "cold_permutations=281 " ++
            "prepared_permutations=0 cold_allocations=0 " ++
            "prepared_allocations=0\n",
        .{
            iterations,
            cold_ns_per_op,
            historical_hot_ns_per_op,
            hot_ns_per_op,
        },
    );
}

fn mutateCachedResult(
    pair: *pair_authority.PreparedTemporalPairAuthorityV1,
    mutation: CachedResultMutation,
) void {
    const result = &pair.prepared_root.result.pair;
    switch (mutation) {
        .format_id => result.format_id[0] ^= 1,
        .protocol_id => result.protocol_id[0] ^= 1,
        .session_id => result.session_id[0] ^= 1,
        .job_id => result.job_id[0] ^= 1,
        .parent_node_index => result.parent_node_index += 1,
        .parent_height => result.parent_height += 1,
        .child_id => result.child_ids[0][0] ^= 1,
    }
}

fn runConvenience(
    pair: *const pair_authority.PreparedTemporalPairAuthorityV1,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u32 = 0;
    for (0..iterations) |_| {
        const result = try temporal.authenticateRoot(
            &pair.prepared_root.authority_snapshot,
            &pair.prepared_root.record_snapshot,
            &pair.prepared_root.pin_snapshot,
        );
        checksum ^= result.pair.node_id[0];
        std.mem.doNotOptimizeAway(&result);
    }
    std.mem.doNotOptimizeAway(&checksum);
    return timer.read();
}

fn runPrepared(
    pair: *const pair_authority.PreparedTemporalPairAuthorityV1,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u32 = 0;
    for (0..iterations) |_| {
        const result = try temporal_source.authenticatePreparedPairForSource(
            pair,
        );
        checksum ^= result.pair.node_id[0];
        std.mem.doNotOptimizeAway(&result);
    }
    std.mem.doNotOptimizeAway(&checksum);
    return timer.read();
}

fn runHistoricalPrepared(
    pair: *const pair_authority.PreparedTemporalPairAuthorityV1,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u32 = 0;
    for (0..iterations) |_| {
        const result = try temporal.authenticateRootWithPreparedContext(
            &pair.prepared_root,
            &pair.prepared_root.authority_snapshot,
            &pair.prepared_root.record_snapshot,
            &pair.prepared_root.pin_snapshot,
        );
        checksum ^= result.pair.node_id[0];
        std.mem.doNotOptimizeAway(&result);
    }
    std.mem.doNotOptimizeAway(&checksum);
    return timer.read();
}

fn preparedPairFixture() !pair_authority.PreparedTemporalPairAuthorityV1 {
    const statements = try adjacentStatements();
    const session_id = digest(101);
    const parent_vk = digest(102);
    const leaf_vk = digest(103);
    const shared_lineage = digest(104);
    const left = try preparedChild(
        statements[0],
        session_id,
        parent_vk,
        leaf_vk,
        digest(105),
        shared_lineage,
        0,
    );
    const right = try preparedChild(
        statements[1],
        session_id,
        parent_vk,
        leaf_vk,
        shared_lineage,
        digest(106),
        1,
    );
    const pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = parent_vk,
    };
    var pair: pair_authority.PreparedTemporalPairAuthorityV1 = undefined;
    try pair_authority.prepareInto(&pair, &left, &right, &pin);
    return pair;
}

fn preparedChild(
    statement: span.SpanStatement,
    session_id: Digest,
    parent_vk: Digest,
    leaf_vk: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    index: u32,
) !child_authority.PreparedTemporalChildV1 {
    const words = try statement.canonicalWords();
    const executed = switch (statement.body) {
        .empty => return error.UnexpectedEmptyStatement,
        .executed => |value| value,
    };
    var child = temporal.VerifiedChildV2{
        .position = try temporal.positionForNextParent(statement),
        .kind = .segment_leaf,
        .scope = .complete_execution,
        .proof_present = true,
        .roster_count = temporal.COMPLETE_ROSTER_COUNT,
        .session_id = session_id,
        .job_id = try temporal.jobId(&words),
        .recursive_parent_vk_id = parent_vk,
        .verification_key_id = leaf_vk,
        .air_program_id = digest(200 + index * 20),
        .manifest_id = digest(201 + index * 20),
        .profile_id = digest(202 + index * 20),
        .statement_words = words,
        .proof_id = digest(203 + index * 20),
        .transcript_id = digest(204 + index * 20),
        .capture_id = digest(205 + index * 20),
        .verifier_receipt_id = digest(206 + index * 20),
        .claimed_sums_id = digest(207 + index * 20),
        .relation_replay_id = digest(208 + index * 20),
        .auxiliary_claim_seal_id = digest(209 + index * 20),
        .closure_receipt_id = digest(210 + index * 20),
        .lineage_id = digest(211 + index * 20),
        .closure_value = .{ 0, 0, 0, 0 },
    };
    child.closure_receipt_id = try temporal.closureReceiptId(&child);
    const child_id = try child.id();
    var prepared = child_authority.PreparedTemporalChildV1{
        .source_publication_id = digest(300 + index * 20),
        .source_verifier_context_id = digest(301 + index * 20),
        .source_closure_receipt_id = child.closure_receipt_id,
        .segment_index = index,
        .segment_count = 2,
        .global_cycle_start = @intCast(executed.first_cycle),
        .global_cycle_end = @intCast(executed.endCycle()),
        .entry_continuation_root = 1_000 + index,
        .exit_continuation_root = 1_001 + index,
        .position_id = digest(302 + index * 20),
        .segment_wire_id = digest(303 + index * 20),
        .entry_lineage_id = entry_lineage_id,
        .exit_lineage_id = exit_lineage_id,
        .child = child,
        .child_id = child_id,
        .admission_id = [_]u32{0} ** recursion.poseidon2_channel.RATE,
    };
    prepared.admission_id = child_authority.expectedAdmissionId(
        prepared.sourceBinding(),
    );
    try prepared.validate();
    return prepared;
}

fn adjacentStatements() ![2]span.SpanStatement {
    const zero_registers = [_]u32{0} ** 32;
    const initial = try span.MachineState.init(
        0x1000,
        zero_registers,
        digest(401),
        digest(402),
    );
    const middle = try span.MachineState.init(
        0x1004,
        zero_registers,
        digest(403),
        digest(404),
    );
    const final = try span.MachineState.init(
        0x1008,
        zero_registers,
        digest(405),
        digest(406),
    );
    const input = digest(407);
    const output = digest(408);
    const complete = try span.CompleteExecution.init(
        protocol.PROTOCOL_ID_WORDS,
        digest(409),
        initial,
        final,
        input,
        output,
        20,
    );
    const job = try span.JobContext.init(complete, 2);
    return .{
        try span.SpanStatement.segmentLeaf(
            job,
            0,
            try span.ExecutedSpan.init(
                0,
                1,
                0,
                10,
                initial,
                middle,
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
                middle,
                final,
                span.EdgeClaim.absent(),
                try span.EdgeClaim.present(output),
            ),
        ),
    };
}

fn digest(value: u32) Digest {
    var result = [_]u32{0} ** recursion.poseidon2_channel.RATE;
    result[0] = value;
    return result;
}

comptime {
    if (pair_authority.HEAP_ALLOCATIONS_PER_PREPARATION != 0 or
        pair_authority.HISTORICAL_VALIDATION_HEAP_ALLOCATIONS != 0 or
        pair_authority.ONE_PASS_VALIDATION_HEAP_ALLOCATIONS != 0 or
        pair_authority.HOT_AUTHENTICATION_HEAP_ALLOCATIONS != 0 or
        pair_authority.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS != 0 or
        pair_authority.HISTORICAL_HOT_SNAPSHOT_EQUALITY_PASSES != 3 or
        pair_authority.HOT_SNAPSHOT_EQUALITY_PASSES != 0 or
        !pair_authority.PREPARED_PAIR_CONTEXT_AMORTIZED)
    {
        @compileError("temporal pair prepared-performance ABI drifted");
    }
}
