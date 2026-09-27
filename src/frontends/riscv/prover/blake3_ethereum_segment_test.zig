//! Two real Ethereum segments, full-memory custody and an independently verified root.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const segment_statement = @import("blake3_segment_statement.zig");
test "BLAKE3 Ethereum adjacent segments prove full custody and aggregate root [compact providers]" {
    try check(.diagnostic_q8_pow0, 3, false, false);
}
test "BLAKE3 Ethereum canonical segments prove full custody and aggregate root [compact providers canonical]" {
    try check(.csp_q70_pow26, 3, false, false);
}
test "BLAKE3 Ethereum precompile boundary proves full custody and aggregate root" {
    try check(.diagnostic_q8_pow0, 4, false, false);
}
test "SHA canonical adjacent segments prove full custody and aggregate root" {
    try check(.csp_q70_pow26, 4, true, false);
}
test "SHA canonical adjacent segments share manifest and prove aggregate root" {
    try check(.csp_q70_pow26, 4, true, true);
}
fn check(comptime profile: parent.protocol.Profile, comptime first_steps: u64, comptime sha: bool, comptime joint: bool) !void {
    const Owner = if (sha) @import("blake3_ethereum_witness.zig").ShaOwner else @import("blake3_ethereum_witness.zig").Owner;
    const Api = if (sha) @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu) else @import("blake3_ethereum_proof.zig").ForBackend(Cpu);
    const Pipeline = if (sha) @import("blake3_segment_parent.zig").ForEthereumShaBackend(Cpu) else @import("blake3_segment_parent.zig").ForEthereumBackend(Cpu);
    var timer = try std.time.Timer.start();
    const config = profile.config();
    const a = std.testing.allocator;
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const elf = if (sha) fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1) else fixture.buildEthereumWithCompletion(.self_loop);
    const Session = if (sha) runner.EthereumShaExecutionSession else runner.EthereumExecutionSession;
    var session = try Session.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(first_steps);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 100);
    defer second.deinit();
    if (sha) {
        try std.testing.expectEqual(@as(usize, 1), first.extension.sha_calls.len());
        try std.testing.expectEqual(@as(usize, 0), first.extension.keccakf_calls.len());
        try std.testing.expectEqual(@as(usize, 1), second.extension.sha_calls.len());
        try std.testing.expectEqual(@as(usize, 1), second.extension.keccakf_calls.len());
    } else {
        try std.testing.expectEqual(@as(usize, 1), first.signer_recovery_calls.len());
        try std.testing.expectEqual(@as(usize, 0), first.keccakf_calls.len());
        try std.testing.expectEqual(@as(usize, 1), second.keccakf_calls.len());
        try std.testing.expectEqual(@as(usize, 0), second.signer_recovery_calls.len());
    }
    try std.testing.expectEqual(first_steps + 1, second.base.global_first_cycle);
    var left = try Owner.initCompactSegment(a, &first);
    var left_alive = true;
    defer if (left_alive) left.deinit();
    var right = try Owner.initCompactSegment(a, &second);
    var right_alive = true;
    defer if (right_alive) right.deinit();
    try std.testing.expectEqualDeep(left.memory.program.root, right.memory.program.root);
    const first_boundary = try segment_statement.boundary(a, &first.base);
    const second_boundary = try segment_statement.boundary(a, &second.base);
    try std.testing.expectEqualDeep(first_boundary.exit, second_boundary.entry);
    const job = try segment_statement.initJob(a, config, &first.base, &second.base, &left.native.statement.public_data, &right.native.statement.public_data);
    const entry = try segment_statement.captureEndpoint(a, &first.base, &left.native.statement.public_data, .entry);
    const exit = try segment_statement.captureEndpoint(a, &second.base, &right.native.statement.public_data, .exit);
    try std.testing.expectEqualDeep(job, try segment_statement.initJobFromEndpoints(config, entry, exit, 2));
    try std.testing.expectError(error.InvalidBlake3Segment, segment_statement.initJobFromEndpoints(config, exit, entry, 2));
    try std.testing.expectError(error.InvalidBlake3Segment, segment_statement.initJobFromEndpoints(config, entry, exit, 0));
    var wrong_program = exit;
    wrong_program.program.bytes[0] ^= 1;
    try std.testing.expectError(error.SegmentProgramMismatch, segment_statement.initJobFromEndpoints(config, entry, wrong_program, 2));
    const statements = [2]span.SpanStatement{
        try segment_statement.leaf(a, job, &first.base),
        try segment_statement.leaf(a, job, &second.base),
    };
    const lkey = try Api.PreparedVerifier.initCompact(a, &left.native.statement, left.statement, try left.admission(), config, left.native.compact_ranges.?.plan);
    defer lkey.deinit();
    const rkey = try Api.PreparedVerifier.initCompact(a, &right.native.statement, right.statement, try right.admission(), config, right.native.compact_ranges.?.plan);
    defer rkey.deinit();
    var wrong = rkey.id;
    wrong[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, Pipeline.preparePairWithPool(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, wrong }, statements, 2, &pool));
    try std.testing.expect(!left.native.interaction_ready and !right.native.interaction_ready);
    try std.testing.expectError(error.AliasedAggregateChildren, Pipeline.preparePairWithPool(a, .{ &left, &left }, .{ lkey, lkey }, .{ lkey.id, lkey.id }, statements, 2, &pool));
    // A bad second witness must not consume the valid first child.
    right.native.interaction_ready = true;
    try std.testing.expectError(error.InvalidExecutionPhase, Pipeline.preparePairWithPool(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, 2, &pool));
    right.native.interaction_ready = false;
    try std.testing.expect(!left.native.interaction_ready);
    right.hashes.plan_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, Pipeline.preparePairWithPool(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, 2, &pool));
    right.hashes.plan_id[0] ^= 1;
    try std.testing.expect(!left.native.interaction_ready and !right.native.interaction_ready);
    left_alive = false;
    right_alive = false;
    var fold = if (joint) blk: {
        const admission = @import("block_execution_admission.zig");
        const context = try admission.context(statements, config);
        const admissions = [2]@import("block_commitment_manifest.zig").Admission{
            try admission.derive(lkey, lkey.id, statements[0], .rv32im_zkvm_ethereum_sha_v1, 0),
            try admission.derive(rkey, rkey.id, statements[1], .rv32im_zkvm_ethereum_sha_v1, 1),
        };
        var forged = admissions;
        forged[1].geometry_id[0] ^= 1;
        try std.testing.expectError(error.InvalidComponentCensus, Pipeline.preparePairWithManifest(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, context, forged, 2, &pool));
        try std.testing.expect(!left.native.interaction_ready and !right.native.interaction_ready);
        break :blk try Pipeline.preparePairOwnedWithManifest(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, context, admissions, 2, &pool);
    } else try Pipeline.preparePairOwnedWithPool(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, 2, &pool);
    var fold_alive = true;
    defer if (fold_alive) fold.deinit();
    binding.deinit();
    binding_alive = false;
    const retained = try fold.prepared.rows.retainedBytes();
    const statement = fold.statement;
    _ = try span.RootStatement.init(statement);
    std.debug.print("{s}_SEGMENTS_PREPARED segments=2 cycles={d} retained_bytes={d}\n", .{ if (sha) "BLAKE3_SHA" else "BLAKE3_ETHEREUM", statement.body.executed.cycle_count, retained });
    const key = try parent.ForBackend(Cpu).deriveKeyWithProfileAndPool(a, &fold.prepared, profile, &pool);
    const expected = try key.identity();
    const admission = try parent.protocol.Admission.init(key, expected);
    const Worker = parent.pipeline.ForBackend(Cpu).Worker;
    const worker = try Worker.init(a, &fold.prepared.rows, admission, .{ .worker_count = 4, .host_byte_limit = @as(usize, if (profile == .csp_q70_pow26) 48 else 24) * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
    var worker_alive = true;
    defer if (worker_alive) worker.deinit();
    var proof = worker.prove(&fold.prepared.rows) catch |err| {
        const failed_usage = worker.budget.snapshot();
        if (worker.workspace.core_diagnostic) |diagnostic| {
            std.debug.print("BLAKE3_PARENT_CORE_FAILURE phase={s} composition_subphase={s} cause={s}\n", .{ @tagName(diagnostic.phase), if (diagnostic.composition_subphase) |subphase| @tagName(subphase) else "none", @errorName(diagnostic.cause) });
        }
        std.debug.print("BLAKE3_PARENT_WORKER_FAILURE phase={s} error={s} peak_bytes={d} limit_bytes={d}\n", .{ @tagName(worker.workspace.phase), @errorName(err), failed_usage.peak_live_bytes, failed_usage.limit });
        return err;
    };
    defer proof.deinit();
    const usage = worker.budget.snapshot();
    worker.deinit();
    worker_alive = false;
    fold.deinit();
    fold_alive = false;
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try parent.tree.Node.verifyOwned(&decoded, admission, expected, statement);
    defer verified.deinit();
    _ = try verified.root();
    try std.testing.expectEqual(@as(usize, config.fri_config.n_queries), verified.verified.capture.queries.raw.len);
    std.debug.print("{s}_SEGMENTS verified=true joint_manifest={any} segments=2 signer={d} keccak=1 sha={d} full_memory_custody=true queries={d} pow_bits={d} artifact_bytes={d} worker_peak_bytes={d} worker_limit_bytes={d} elapsed_ns={d} witnesses_and_worker_released=true\n", .{ if (sha) "BLAKE3_SHA" else "BLAKE3_ETHEREUM", joint, @as(u32, if (sha) 0 else 1), @as(u32, if (sha) 2 else 0), config.fri_config.n_queries, config.pow_bits, bytes.len, usage.peak_live_bytes, usage.limit, timer.read() });
}
