//! Explicit q70/PoW26 parent proof and recursive transcript replay. Callers
//! supply either diagnostic or canonical children; report their actual parameters.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("../recursion/blake3_execution_parent_proof.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub fn check(a: std.mem.Allocator, prepared: *api.preparation.Prepared) !void {
    return checkWithBudget(a, prepared, 8 * 1024 * 1024 * 1024);
}
pub fn checkWithBudget(a: std.mem.Allocator, prepared: *api.preparation.Prepared, host_byte_limit: usize) !void {
    return checkWithBackend(Cpu, a, prepared, host_byte_limit);
}
pub fn checkWithBackend(comptime Backend: type, a: std.mem.Allocator, prepared: *api.preparation.Prepared, host_byte_limit: usize) !void {
    return checkWithBackendDepth(Backend, a, prepared, host_byte_limit, true);
}
fn checkWithBackendDepth(comptime Backend: type, a: std.mem.Allocator, prepared: *api.preparation.Prepared, host_byte_limit: usize, allow_next: bool) anyerror!void {
    const workers = try benchmarkWorkerCount(a);
    const Parent = api.ForBackend(Backend);
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
    const Worker = api.pipeline.ForBackend(Backend).Worker;
    const worker = try Worker.init(a, &prepared.rows, old, .{ .worker_count = workers, .host_byte_limit = host_byte_limit, .retained_scratch_limit = 64 * 1024 * 1024 });
    var alive = true;
    defer if (alive) worker.deinit();
    const original_plan = worker.plan;
    var wrong_root = key;
    wrong_root.preprocessed_root[0] ^= 1;
    const wrong_admission = try api.protocol.Admission.init(wrong_root, try wrong_root.identity());
    try std.testing.expect(!try worker.plan.tryRebindAdmission(&prepared.rows, wrong_admission));
    try std.testing.expectEqualSlices(u8, &diagnostic_id, &worker.plan.admission.expected_id);
    try std.testing.expectError(error.UntrustedBlake3ParentKey, worker.plan.tryRebindAdmission(&prepared.rows, .{ .key = key, .expected_id = diagnostic_id }));
    const before = if (comptime Backend != Cpu) try Backend.telemetrySnapshot() else {};
    var proof = worker.proveAdmitted(&prepared.rows, admission) catch |err| {
        std.debug.print("NATIVE_PARENT_FAILURE phase={s} error={s}\n", .{ @tagName(worker.workspace.phase), @errorName(err) });
        if (worker.workspace.core_diagnostic) |d| std.debug.print("NATIVE_PARENT_CORE_FAILURE phase={s} subphase={s} cause={s}\n", .{ @tagName(d.phase), if (d.composition_subphase) |v| @tagName(v) else "none", @errorName(d.cause) });
        return err;
    };
    defer proof.deinit();
    try std.testing.expect(worker.plan == original_plan);
    try std.testing.expectEqualSlices(u8, &expected, &worker.plan.admission.expected_id);
    try std.testing.expectEqual(workers, worker.pool.workerCount());
    std.debug.print("CANONICAL_PARENT_WORKERS count={d} host_cpus={d}\n", .{ workers, try std.Thread.getCpuCount() });
    if (comptime Backend != Cpu) {
        const delta = (try Backend.telemetrySnapshot()).delta(before);
        try delta.requireMetalDispatch();
        inline for (@typeInfo(@TypeOf(delta.counters)).@"struct".fields) |field| {
            const count = @field(delta.counters, field.name);
            if (count != 0) std.debug.print("NATIVE_PARENT_DEVICE_WORK {s}={d}\n", .{ field.name, count });
        }
        std.debug.print("NATIVE_PARENT_METAL dispatches={d} fallbacks={d}\n", .{ delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal() });
    }
    const memory = worker.budget.snapshot();
    std.debug.print("CANONICAL_PARENT_MEMORY peak_bytes={d} limit_bytes={d}\n", .{ memory.peak_live_bytes, memory.limit });
    worker.deinit();
    alive = false;
    const bytes = try api.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        std.debug.print("BLAKE3_PARENT_ARTIFACT_SHA256 {s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    }
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
    if (allow_next and (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_NEXT_PREPARATION") or std.process.hasEnvVarConstant("STWO_RISCV_PARENT_NEXT_PROOF"))) {
        const limit: usize = 24 * 1024 * 1024 * 1024;
        var timer = try std.time.Timer.start();
        var next = try api.preparation.prepareBounded(a, &admission, &verified, expected, 2, limit);
        defer next.deinit();
        const elapsed = timer.read();
        try std.testing.expectEqualSlices(u8, &expected, &next.context.child_key_id);
        try std.testing.expectEqual(@as(usize, 70), next.context.child_config.fri_config.n_queries);
        try std.testing.expectEqual(@as(u32, 26), next.context.child_config.pow_bits);
        const next_memory = next.allocation_budget.?.snapshot();
        try std.testing.expect(next_memory.peak_live_bytes <= limit);
        const roster = @import("../recursion/air/blake3_native_parent_rows.zig");
        var main_bytes: usize = 0;
        inline for (roster.Airs, 0..) |Air, i| {
            for (next.rows.main[i]) |column| main_bytes += column.values.len * @sizeOf(core.fields.m31.M31);
            std.debug.print("CANONICAL_NEXT_COHORT index={d} name={s} live={d} padded={d} main_columns={d}\n", .{ i, @typeName(Air), next.rows.fixed[i].len, next.rows.main[i][0].values.len, Air.PHYSICAL_MAIN_COLUMN_COUNT });
        }
        std.debug.print("CANONICAL_NEXT_PREPARATION child_queries=70 child_pow_bits=26 preparation_ns={d} retained_bytes={d} main_bytes={d} peak_bytes={d} limit_bytes={d} parent_proved=false\n", .{ elapsed, try next.retainedBytes(), main_bytes, next_memory.peak_live_bytes, limit });
        if (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_NEXT_PROOF")) {
            timer.reset();
            try checkWithBackendDepth(Backend, a, &next, host_byte_limit, false);
            std.debug.print("CANONICAL_NEXT_PROOF queries=70 pow_bits=26 proof_and_checks_ns={d} independently_verified=true\n", .{timer.read()});
        }
    }
    std.debug.print("BLAKE3_PARENT_PROFILE verified=true queries=70 pow_bits=26 artifact_bytes={d} successful_worker_rekey=true fixed_plan_reused=true outputs_outlive_worker=true transcript_replayed=true transcript_g_rows={d} child_queries={d} child_pow_bits={d}\n", .{ bytes.len, counts.g, prepared.context.child_config.fri_config.n_queries, prepared.context.child_config.pow_bits });
}

/// Qualification override only; production workers receive admitted policy counts.
/// Keep two workers as the ordinary test default and reject oversubscription.
pub fn benchmarkWorkerCount(a: std.mem.Allocator) !usize {
    const value = std.process.getEnvVarOwned(a, "STWO_RISCV_PARENT_BENCH_WORKERS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return 2,
        else => return err,
    };
    defer a.free(value);
    const count = std.fmt.parseInt(usize, value, 10) catch return error.InvalidParentBenchmarkWorkers;
    if (count == 0 or count > try std.Thread.getCpuCount()) return error.InvalidParentBenchmarkWorkers;
    return count;
}

/// Keep leak-checking test allocation by default; opt into the production heap
/// explicitly for performance comparisons, without changing worker budget caps.
pub fn benchmarkAllocator() !std.mem.Allocator {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_RISCV_PARENT_BENCH_ALLOCATOR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            std.debug.print("CANONICAL_PARENT_ALLOCATOR mode=testing\n", .{});
            return std.testing.allocator;
        },
        else => return err,
    };
    defer std.heap.page_allocator.free(value);
    if (!std.mem.eql(u8, value, "smp")) return error.InvalidParentBenchmarkAllocator;
    std.debug.print("CANONICAL_PARENT_ALLOCATOR mode=smp\n", .{});
    return std.heap.smp_allocator;
}
