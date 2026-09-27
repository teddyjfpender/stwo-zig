//! Explicit q70/PoW26 parent proof and recursive transcript replay. The child
//! fixture remains diagnostic; this does not qualify the whole chain's security.
const std = @import("std");
const api = @import("../recursion/blake3_execution_parent_proof.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Parent = api.ForBackend(Cpu);
pub fn check(a: std.mem.Allocator, prepared: *const api.preparation.Prepared) !void {
    return checkWithBudget(a, prepared, 8 * 1024 * 1024 * 1024);
}
pub fn checkWithBudget(a: std.mem.Allocator, prepared: *const api.preparation.Prepared, host_byte_limit: usize) !void {
    const diagnostic = try Parent.deriveKey(a, prepared);
    const key = try Parent.deriveKeyWithProfile(a, prepared, .csp_q70_pow26);
    const expected = try key.identity();
    const diagnostic_id = try diagnostic.identity();
    try std.testing.expect(!std.mem.eql(u8, &expected, &diagnostic_id));
    // Query/PoW changes retain this profile's evaluation domain, but must still
    // select a distinct admitted key and transcript.
    try std.testing.expectEqualSlices(u8, &diagnostic.preprocessed_root, &key.preprocessed_root);
    const admission = try api.protocol.Admission.init(key, expected);
    const old = try api.protocol.Admission.init(diagnostic, diagnostic_id);
    try std.testing.expectError(error.UntrustedBlake3ParentKey, api.protocol.Admission.init(key, diagnostic_id));
    var changed = key;
    changed.profile = .diagnostic_q8_pow0;
    try std.testing.expectError(error.InvalidBlake3ParentProfile, changed.identity());
    changed = key;
    changed.config.pow_bits = 25;
    try std.testing.expectError(error.InvalidBlake3ParentProfile, changed.identity());
    changed = key;
    changed.config.fri_config.n_queries = 69;
    try std.testing.expectError(error.InvalidBlake3ParentProfile, changed.identity());
    changed = key;
    changed.config.lifting_log_size = 0;
    try std.testing.expectError(error.InvalidBlake3ParentProfile, changed.identity());
    const Worker = api.pipeline.ForBackend(Cpu).Worker;
    const worker = try Worker.init(a, &prepared.rows, old, .{ .worker_count = 2, .host_byte_limit = host_byte_limit, .retained_scratch_limit = 64 * 1024 * 1024 });
    var alive = true;
    defer if (alive) worker.deinit();
    const original_plan = worker.plan;
    var wrong_root = key;
    wrong_root.preprocessed_root[0] ^= 1;
    const wrong_admission = try api.protocol.Admission.init(wrong_root, try wrong_root.identity());
    try std.testing.expect(!try worker.plan.tryRebindAdmission(&prepared.rows, wrong_admission));
    try std.testing.expectEqualSlices(u8, &diagnostic_id, &worker.plan.admission.expected_id);
    try std.testing.expectError(error.UntrustedBlake3ParentKey, worker.plan.tryRebindAdmission(&prepared.rows, .{ .key = key, .expected_id = diagnostic_id }));
    var proof = try worker.proveAdmitted(&prepared.rows, admission);
    defer proof.deinit();
    try std.testing.expect(worker.plan == original_plan);
    try std.testing.expectEqualSlices(u8, &expected, &worker.plan.admission.expected_id);
    try std.testing.expectEqual(@as(usize, 2), worker.pool.workerCount());
    const memory = worker.budget.snapshot();
    std.debug.print("CANONICAL_PARENT_MEMORY peak_bytes={d} limit_bytes={d}\n", .{ memory.peak_live_bytes, memory.limit });
    worker.deinit();
    alive = false;
    const bytes = try api.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    try std.testing.expectError(error.UntrustedBlake3ParentKey, api.codec.decode(a, bytes, &old));
    var original = try api.verify(&proof, &admission);
    defer original.deinit();
    try std.testing.expect(original.allocation_budget != null);
    var decoded = try api.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try api.verify(&decoded, &admission);
    defer verified.deinit();
    try verified.validate(&admission, expected);
    try std.testing.expectEqual(@as(usize, 70), verified.capture.queries.raw.len);
    try std.testing.expectEqual(@as(u32, 26), admission.key.config.pow_bits);
    var planned = try @import("../recursion/air/blake3_parent_transcript.zig").planReplay(a, &admission, &verified, 2);
    var planned_alive = true;
    defer if (planned_alive) planned.deinit();
    const counts = try planned.hashCounts();
    var replay = try planned.emit(a);
    planned_alive = false;
    defer replay.deinit();
    try std.testing.expectEqualSlices(u8, &verified.channel.digestBytes(), &replay.end.digestBytes());
    try std.testing.expectEqual(verified.channel.n_draws, replay.end.n_draws);
    std.debug.print("BLAKE3_PARENT_PROFILE verified=true queries=70 pow_bits=26 artifact_bytes={d} successful_worker_rekey=true fixed_plan_reused=true outputs_outlive_worker=true transcript_replayed=true transcript_g_rows={d} child_queries={d} child_pow_bits={d}\n", .{ bytes.len, counts.g, prepared.context.child_config.fri_config.n_queries, prepared.context.child_config.pow_bits });
}
