//! Two real Ethereum segments, full-memory custody and an independently verified root.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Owner = @import("blake3_ethereum_witness.zig").Owner;
const Api = @import("blake3_ethereum_proof.zig").ForBackend(Cpu);
const Pipeline = @import("blake3_segment_parent.zig").ForEthereumBackend(Cpu);
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const segment_statement = @import("blake3_segment_statement.zig");
test "BLAKE3 Ethereum adjacent segments prove full custody and aggregate root" {
    try check(.diagnostic_q8_pow0);
}
test "BLAKE3 Ethereum canonical segments prove full custody and aggregate root" {
    try check(.csp_q70_pow26);
}
fn check(comptime profile: parent.protocol.Profile) !void {
    const config = profile.config();
    const a = std.testing.allocator;
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildEthereumWithCompletion(.self_loop);
    var session = try runner.EthereumExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(3);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 100);
    defer second.deinit();
    try std.testing.expectEqual(@as(usize, 1), first.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 0), first.keccakf_calls.len());
    try std.testing.expectEqual(@as(usize, 1), second.keccakf_calls.len());
    try std.testing.expectEqual(@as(usize, 0), second.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(u64, 4), second.base.global_first_cycle);
    var left = try Owner.initSegment(a, &first);
    var left_alive = true;
    defer if (left_alive) left.deinit();
    var right = try Owner.initSegment(a, &second);
    var right_alive = true;
    defer if (right_alive) right.deinit();
    try std.testing.expectEqualDeep(left.memory.program.root, right.memory.program.root);
    const first_boundary = try segment_statement.boundary(a, &first.base);
    const second_boundary = try segment_statement.boundary(a, &second.base);
    try std.testing.expectEqualDeep(first_boundary.exit, second_boundary.entry);
    const job = try segment_statement.initJob(a, config, &first.base, &second.base, &left.native.statement.public_data, &right.native.statement.public_data);
    const statements = [2]span.SpanStatement{
        try segment_statement.leaf(a, job, &first.base),
        try segment_statement.leaf(a, job, &second.base),
    };
    const lkey = try Api.PreparedVerifier.init(a, &left.native.statement, left.statement, try left.admission(), config);
    defer lkey.deinit();
    const rkey = try Api.PreparedVerifier.init(a, &right.native.statement, right.statement, try right.admission(), config);
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
    var fold = try Pipeline.preparePairWithPool(a, .{ &left, &right }, .{ lkey, rkey }, .{ lkey.id, rkey.id }, statements, 2, &pool);
    var fold_alive = true;
    defer if (fold_alive) fold.deinit();
    left.deinit();
    left_alive = false;
    right.deinit();
    right_alive = false;
    binding.deinit();
    binding_alive = false;
    const retained = try fold.prepared.rows.retainedBytes();
    const statement = fold.statement;
    _ = try span.RootStatement.init(statement);
    std.debug.print("BLAKE3_ETHEREUM_SEGMENTS_PREPARED segments=2 cycles={d} retained_bytes={d}\n", .{ statement.body.executed.cycle_count, retained });
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
    std.debug.print("BLAKE3_ETHEREUM_SEGMENTS verified=true segments=2 signer=1 keccak=1 full_memory_custody=true queries={d} pow_bits={d} artifact_bytes={d} worker_peak_bytes={d} worker_limit_bytes={d} witnesses_and_worker_released=true\n", .{ config.fri_config.n_queries, config.pow_bits, bytes.len, usage.peak_live_bytes, usage.limit });
}
