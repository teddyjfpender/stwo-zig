//! Canonical single-level preparation/proving overlap using real typed captures.
const std = @import("std");
const api = @import("../recursion/blake3_execution_parent_proof.zig");
const GiB = 1024 * 1024 * 1024;
pub fn check(comptime Backend: type, a: std.mem.Allocator, verifier: anytype, capture: anytype, seed: *api.preparation.Prepared) !void {
    const Pipeline = api.execution_pipeline.ForBackend(Backend, @TypeOf(verifier.*), @TypeOf(capture.*));
    const workers = try @import("blake3_parent_profile_test_support.zig").benchmarkWorkerCount(a);
    const key = try api.ForBackend(Backend).deriveKeyWithProfile(a, seed, .csp_q70_pow26);
    const expected = try key.identity();
    const admission = try api.protocol.Admission.init(key, expected);
    const job = Pipeline.Job{ .verifier = verifier, .capture = capture, .expected_child_id = verifier.id, .admission = admission, .capacity = 2 };
    const Policy = @import("blake3_pipeline_test_policy.zig").Policy;
    const policy = Policy{ .total_cpu_tokens = workers + 1, .cpu_tokens_per_node = workers + 1, .proof_worker_count = workers, .total_rss_bytes = 60 * GiB, .rss_bytes_per_node = 60 * GiB };
    const sizing = api.execution_pipeline.Sizing{ .preparation_bytes = 12 * GiB, .worker_bytes = 24 * GiB, .queued_bytes = try std.math.add(usize, try seed.rows.retainedBytes(), 64 * 1024 * 1024), .external_reserved_bytes = 12 * GiB };
    _ = try Pipeline.admit(&policy, sizing, 2);
    var excessive = sizing;
    excessive.external_reserved_bytes = 60 * GiB;
    try std.testing.expectError(error.ParentPipelineMemoryBudgetExceeded, Pipeline.admit(&policy, excessive, 2));
    var cpu_limited = policy;
    cpu_limited.total_cpu_tokens = workers;
    cpu_limited.cpu_tokens_per_node = workers;
    try std.testing.expectError(error.ParentPipelineCpuBudgetExceeded, Pipeline.admit(&cpu_limited, sizing, 2));
    const worker = try Pipeline.Worker.init(a, &seed.rows, admission, .{ .worker_count = workers, .host_byte_limit = sizing.worker_bytes, .retained_scratch_limit = 64 * 1024 * 1024 });
    var alive = true;
    defer if (alive) worker.deinit();
    const plan = worker.plan;
    const fixed = plan.fixed_commitment.columns.ptr;
    var denied = sizing;
    denied.preparation_bytes = 1;
    try std.testing.expectError(error.PreparationHostBudgetExceeded, Pipeline.run(a, &policy, denied, worker, &.{job}));
    var corrupt = job;
    corrupt.admission.expected_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentKey, Pipeline.run(a, &policy, sizing, worker, &.{corrupt}));
    const serial = std.process.hasEnvVarConstant("STWO_RISCV_PARENT_PIPELINE_SERIAL");
    var first_report: ?api.execution_pipeline.Report = null;
    defer if (first_report) |*first| first.deinit();
    const begin = try std.time.Instant.now();
    // Same persistent worker, keys, inputs and limits. The serial control drains
    // the first job before starting the second through the same bounded runner.
    var report = if (serial) blk: {
        first_report = try Pipeline.run(a, &policy, sizing, worker, &.{job});
        break :blk try Pipeline.run(a, &policy, sizing, worker, &.{job});
    } else try Pipeline.run(a, &policy, sizing, worker, &.{ job, job });
    const pipeline_ns = (try std.time.Instant.now()).since(begin);
    defer report.deinit();
    try std.testing.expectEqual(@as(usize, 2), report.outputs.len + if (first_report) |first| first.outputs.len else @as(usize, 0));
    if (serial) {
        try std.testing.expectEqual(@as(u64, 0), report.overlapNs() + first_report.?.overlapNs());
    } else try std.testing.expect(report.overlapNs() > 0);
    try std.testing.expectEqual(plan, worker.plan);
    try std.testing.expectEqual(fixed, worker.plan.fixed_commitment.columns.ptr);
    try std.testing.expect(worker.workspace.arena.queryCapacity() <= worker.workspace.retained_limit);
    const usage = worker.budget.snapshot();
    try std.testing.expect(usage.peak_live_bytes <= usage.limit);
    worker.deinit();
    alive = false;
    var first_digest: ?[32]u8 = null;
    const batches = [_][]api.artifact.Owned{ if (first_report) |first| first.outputs else &.{}, report.outputs };
    var index: usize = 0;
    for (batches) |outputs| for (outputs) |*output| {
        // Verification consumes artifact ownership; encode before transferring it.
        const bytes = try api.codec.encode(a, output, &admission);
        defer a.free(bytes);
        var verified = try api.verify(output, &admission);
        defer verified.deinit();
        try verified.validate(&admission, expected);
        try std.testing.expectEqual(@as(usize, 70), verified.capture.queries.raw.len);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (first_digest) |prior| try std.testing.expectEqualSlices(u8, &prior, &digest) else first_digest = digest;
        var decoded = try api.codec.decode(a, bytes, &admission);
        defer decoded.deinit();
        var fresh = try api.verify(&decoded, &admission);
        defer fresh.deinit();
        try fresh.validate(&admission, expected);
        std.debug.print("CANONICAL_PIPELINE_ARTIFACT index={d} sha256={s} bytes={d} independently_verified=true\n", .{ index, std.fmt.bytesToHex(digest, .lower), bytes.len });
        index += 1;
    };
    std.debug.print("CANONICAL_EXECUTION_PIPELINE mode={s} jobs=2 workers={d} cpu_tokens={d} reserved_bytes={d} wall_ns={d} overlap_ns={d} worker_peak_bytes={d} worker_limit_bytes={d} child_queries={d} child_pow_bits={d} parent_queries=70 parent_pow_bits=26 plan_reused=true outputs_outlive_worker=true independently_verified=true\n", .{ if (serial) "serial" else "overlapped", workers, report.admission.cpu_tokens, report.admission.reserved_bytes, pipeline_ns, report.overlapNs(), usage.peak_live_bytes, usage.limit, seed.context.child_config.fri_config.n_queries, seed.context.child_config.pow_bits });
    if (first_report) |first| for (first.spans, 0..) |span, i| std.debug.print("CANONICAL_PIPELINE_SPAN run=0 index={d} prepare_start={d} prepare_end={d} prove_start={d} prove_end={d}\n", .{ i, span.preparation.start, span.preparation.end, span.proving.start, span.proving.end });
    for (report.spans, 0..) |span, i| std.debug.print("CANONICAL_PIPELINE_SPAN run={d} index={d} prepare_start={d} prepare_end={d} prove_start={d} prove_end={d}\n", .{ @intFromBool(serial), i, span.preparation.start, span.preparation.end, span.proving.start, span.proving.end });
}
