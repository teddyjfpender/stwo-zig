//! Real tree preparation/proving overlap, bounded failure and output custody.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const api = @import("../recursion/blake3_execution_parent_proof.zig");
const tree = api.tree;
const pipeline = api.pipeline;
const Pipeline = pipeline.ForBackend(Cpu);
const GiB = 1024 * 1024 * 1024;
pub fn check(a: std.mem.Allocator, left: *const tree.Node, right: *const tree.Node, folded: *api.aggregation.Fold) !tree.Node {
    const key = try api.ForBackend(Cpu).deriveKey(a, &folded.prepared);
    const expected = try key.identity();
    const admitted = try api.protocol.Admission.init(key, expected);
    const job = pipeline.Job{ .left = left, .right = right, .admission = admitted, .capacity = 2 };
    const policy = TestPolicy{ .total_cpu_tokens = 4, .cpu_tokens_per_node = 4, .proof_worker_count = 2, .total_rss_bytes = 32 * GiB, .rss_bytes_per_node = 32 * GiB };
    const sizing = pipeline.Sizing{ .preparation_workers = 2, .preparation_bytes = 8 * GiB, .worker_bytes = 8 * GiB, .queued_bytes = 2 * GiB, .external_reserved_bytes = 4 * GiB };
    var serial = sizing;
    serial.preparation_workers = 1;
    const serial_admission = try Pipeline.admit(&policy, serial, 2);
    const parallel_admission = try Pipeline.admit(&policy, sizing, 2);
    try std.testing.expectEqual(serial_admission.cpu_tokens + 1, parallel_admission.cpu_tokens);
    try std.testing.expectEqual(serial_admission.reserved_bytes + @import("stwo_prover_engine").work_pool.WORKER_STACK_SIZE, parallel_admission.reserved_bytes);
    var invalid = sizing;
    invalid.preparation_workers = 0;
    try std.testing.expectError(error.InvalidParentPipelineLimits, Pipeline.admit(&policy, invalid, 2));
    invalid.preparation_workers = 3;
    try std.testing.expectError(error.InvalidParentPipelineLimits, Pipeline.admit(&policy, invalid, 2));
    var excessive = sizing;
    excessive.external_reserved_bytes = 32 * GiB;
    try std.testing.expectError(error.ParentPipelineMemoryBudgetExceeded, Pipeline.admit(&policy, excessive, 2));
    const cpu_limited = TestPolicy{ .total_cpu_tokens = 3, .cpu_tokens_per_node = 3, .proof_worker_count = 2, .total_rss_bytes = 32 * GiB, .rss_bytes_per_node = 32 * GiB };
    try std.testing.expectError(error.ParentPipelineCpuBudgetExceeded, Pipeline.admit(&cpu_limited, sizing, 2));
    const worker = try Pipeline.Worker.init(a, &folded.prepared.rows, admitted, .{ .worker_count = 2, .host_byte_limit = sizing.worker_bytes, .retained_scratch_limit = 64 * 1024 * 1024 });
    var alive = true;
    defer if (alive) worker.deinit();
    const original_plan = worker.plan;
    const columns = worker.plan.fixed_commitment.columns.ptr;
    // A failed replacement cannot discard the old authenticated plan.
    var wrong = key;
    wrong.preprocessed_root[31] ^= 1;
    const wrong_admission = try api.protocol.Admission.init(wrong, try wrong.identity());
    try std.testing.expectError(error.UntrustedBlake3ParentRoot, worker.proveAdmitted(&folded.prepared.rows, wrong_admission));
    try std.testing.expectEqual(original_plan, worker.plan);
    {
        var lease = try worker.acquire();
        defer lease.deinit();
        try std.testing.expectError(error.ParentWorkerAlreadyLeased, worker.acquire());
        // Busy admission must precede preparation and allocation, even when the
        // competing caller cannot allocate a single byte.
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.ParentWorkerAlreadyLeased, Pipeline.run(failing.allocator(), &policy, sizing, worker, &.{job}));
        try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
        try std.testing.expectError(error.ParentWorkerAlreadyLeased, worker.proveAdmitted(&folded.prepared.rows, admitted));
    }
    var denied = sizing;
    denied.preparation_bytes = 1;
    try std.testing.expectError(error.PreparationHostBudgetExceeded, Pipeline.run(a, &policy, denied, worker, &.{job}));
    {
        var recovered = try worker.acquire();
        recovered.deinit();
    }
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Pipeline.run(failing.allocator(), &policy, sizing, worker, &.{job}));
    {
        var recovered = try worker.acquire();
        recovered.deinit();
    }
    var report = try Pipeline.run(a, &policy, sizing, worker, &.{ job, job });
    defer report.deinit();
    try std.testing.expectEqual(@as(usize, 2), report.outputs.len);
    try std.testing.expect(report.overlapNs() > 0);
    try std.testing.expectEqual(@as(usize, 2), report.admission.preparation_workers);
    try std.testing.expectEqual(original_plan, worker.plan);
    try std.testing.expectEqual(columns, worker.plan.fixed_commitment.columns.ptr);
    try std.testing.expect(worker.workspace.arena.queryCapacity() <= worker.workspace.retained_limit);
    const usage = worker.budget.snapshot();
    try std.testing.expect(usage.peak_live_bytes <= usage.limit);
    worker.deinit();
    alive = false;
    // Verify both outputs after worker destruction, including a codec copy.
    const bytes = try api.codec.encode(a, &report.outputs[1], &admitted);
    defer a.free(bytes);
    var decoded = try api.codec.decode(a, bytes, &admitted);
    defer decoded.deinit();
    var copied = try tree.Node.verifyOwned(&decoded, admitted, expected, folded.statement);
    defer copied.deinit();
    _ = try copied.root();
    var second = try tree.Node.verifyOwned(&report.outputs[1], admitted, expected, folded.statement);
    defer second.deinit();
    try std.testing.expect(second.verified.allocation_budget != null);
    _ = try second.root();
    var result = try tree.Node.verifyOwned(&report.outputs[0], admitted, expected, folded.statement);
    errdefer result.deinit();
    try std.testing.expect(result.verified.allocation_budget != null);
    _ = try result.root();
    std.debug.print("BLAKE3_TREE_PIPELINE verified=true jobs=2 preparation_workers=2 cpu_tokens={d} reserved_bytes={d} overlap_ns={d} worker_peak_bytes={d} worker_limit_bytes={d} root_artifact_bytes={d} plan_reused=true outputs_outlive_worker=true\n", .{ report.admission.cpu_tokens, report.admission.reserved_bytes, report.overlapNs(), usage.peak_live_bytes, usage.limit, bytes.len });
    return result;
}

const TestPolicy = @import("blake3_pipeline_test_policy.zig").Policy;
