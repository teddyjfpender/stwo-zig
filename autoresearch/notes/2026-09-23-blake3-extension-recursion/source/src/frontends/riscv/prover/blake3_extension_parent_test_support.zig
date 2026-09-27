const std = @import("std");
pub fn check(comptime canonical: bool, a: std.mem.Allocator, admitted: anytype, captured: anytype, expected: [32]u8, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !void {
    const parent = @import("../recursion/blake3_execution_parent_proof.zig");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var prepared = try parent.preparation.prepare(a, admitted, captured, expected, 2);
    var prepared_alive = true;
    defer if (prepared_alive) prepared.deinit();
    std.debug.print("BLAKE3_EXTENSION_PARENT_PREPARED retained_bytes={d} inputs={d}\n", .{ try prepared.rows.retainedBytes(), prepared.rows.input_count });
    const profile: parent.protocol.Profile = if (canonical) .csp_q70_pow26 else .diagnostic_q8_pow0;
    try std.testing.expectEqualDeep(profile.config(), admitted.config);
    const key = try parent.ForBackend(Cpu).deriveKeyWithProfileAndPool(a, &prepared, profile, pool);
    const parent_id = try key.identity();
    const admission = try parent.protocol.Admission.init(key, parent_id);
    const Worker = parent.pipeline.ForBackend(Cpu).Worker;
    const worker = try Worker.init(a, &prepared.rows, admission, .{ .worker_count = 4, .host_byte_limit = @as(usize, if (canonical) 36 else 24) * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
    var worker_alive = true;
    defer if (worker_alive) worker.deinit();
    var proof = worker.prove(&prepared.rows) catch |err| {
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
    prepared.deinit();
    prepared_alive = false;
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try parent.verify(&decoded, &admission);
    defer verified.deinit();
    try verified.validate(&admission, parent_id);
    try std.testing.expectEqual(@as(usize, profile.config().fri_config.n_queries), verified.capture.queries.raw.len);
    std.debug.print("BLAKE3_EXTENSION_PARENT verified=true leaf_queries={d} parent_queries={d} pow_bits={d} artifact_bytes={d} worker_peak_bytes={d} worker_limit_bytes={d} worker_and_rows_released=true\n", .{ admitted.config.fri_config.n_queries, profile.config().fri_config.n_queries, profile.config().pow_bits, bytes.len, usage.peak_live_bytes, usage.limit });
}
