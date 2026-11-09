//! Metal runtime boundary for the shared detached recursive parent transaction.
//! The independent CPU verifier consumes the same admitted key and proof ABI.
const std = @import("std");
const metal = @import("stwo_metal_backend");
const Backend = metal.MetalCommitBackend;
const Engine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(Backend);
const producer = @import("stwo_riscv_detached_parent_producer");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 5 or !std.mem.eql(u8, args[1], "--aot-bundle") or
        !std.mem.eql(u8, args[3], "--aot-manifest-sha256") or args[4].len != 64)
        return error.ExpectedAotBundleAndManifestSha256;
    var tail: usize = 5;
    var selected_aot: metal.shaders.aot_profile.Profile = .core_v2;
    if (args.len > tail and std.mem.eql(u8, args[tail], "--aot-profile")) {
        if (args.len <= tail + 1) return error.MissingAotProfile;
        const value = args[tail + 1];
        selected_aot = if (std.mem.eql(u8, value, "core-v2")) .core_v2 else if (std.mem.eql(u8, value, "recursive-framework-v1")) .recursive_framework_v1 else return error.InvalidAotProfile;
        tail += 2;
    }
    const is_worker = args.len == tail + 3 and std.mem.eql(u8, args[tail], "--worker");
    var batch_input: ?producer.batch.Admitted = if (args.len == tail + 3 and (is_worker or std.mem.eql(u8, args[tail], "--batch"))) try producer.batch.admit(allocator, args[tail + 1], args[tail + 2]) else null;
    defer if (batch_input) |*input| input.deinit();
    const input = if (batch_input == null) try producer.parseArguments(args[tail..]) else null;
    try Backend.admitHostProving(.recursive_preparation);
    var manifest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&manifest, args[4]);
    try @import("aot_bundle_admission.zig").validate(allocator, args[2], manifest);
    if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeAlreadyInitialized;
    try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{
        .bundle_path = args[2],
        .manifest_sha256 = manifest,
        .profile = selected_aot,
    } });
    defer if (Backend.runtimeLifecycleSnapshot().initialized) {
        Backend.shutdown() catch unreachable;
    };
    const before = try Backend.telemetrySnapshot();
    const lifecycle = Backend.runtimeLifecycleSnapshot();
    const identity = lifecycle.identity orelse return error.AuthenticatedMetalRuntimeMissing;
    if (identity.origin != .authenticated_core_aot or identity.manifest_sha256 == null or
        !std.meta.eql(identity.manifest_sha256.?, manifest) or
        !std.meta.eql(identity.source_sha256, selected_aot.sourceDigest()))
        return error.AuthenticatedMetalRuntimeMismatch;
    if (is_worker) {
        // Every response is guarded while the authenticated runtime stays resident.
        const Guard = struct {
            telemetry: @TypeOf(before),
            lifecycle: @TypeOf(lifecycle),
            pub fn check(self: *@This()) !void {
                const now = Backend.runtimeLifecycleSnapshot();
                if (!std.meta.eql(now.identity, self.lifecycle.identity) or now.active_call_leases != 0 or
                    now.initialization_count != self.lifecycle.initialization_count or now.shutdown_count != self.lifecycle.shutdown_count)
                    return error.MetalRuntimeChanged;
                const telemetry = try Backend.telemetrySnapshot();
                const delta = telemetry.delta(self.telemetry);
                try delta.requireMetalDispatch();
                if (delta.counters.metal_poseidon2_merkle_commits == 0) return error.MetalPoseidonDispatchMissing;
                self.telemetry = telemetry;
            }
        };
        var guard = Guard{ .telemetry = before, .lifecycle = lifecycle };
        try producer.worker.serve(Engine, allocator, &batch_input.?, &guard);
        try Backend.shutdown();
        if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeNotReleased;
        std.debug.print("DETACHED_PARENT_METAL_WORKER runtime_released=true\n", .{});
        return;
    }
    var batch_report: ?producer.batch.Report = null;
    defer if (batch_report) |*report| report.deinit();
    const report = if (input) |single| try producer.runWithEngine(Engine, allocator, single) else blk: {
        batch_report = try producer.batch.run(Engine, allocator, &batch_input.?);
        break :blk null;
    };
    const after = Backend.runtimeLifecycleSnapshot();
    if (!std.meta.eql(after.identity, lifecycle.identity) or after.active_call_leases != 0 or
        after.initialization_count != lifecycle.initialization_count or after.shutdown_count != lifecycle.shutdown_count)
        return error.MetalRuntimeChanged;
    const delta = (try Backend.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    if (delta.counters.metal_poseidon2_merkle_commits == 0) return error.MetalPoseidonDispatchMissing;
    try Backend.shutdown();
    if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeNotReleased;
    std.debug.print("DETACHED_PARENT_METAL dispatches={d} poseidon_commits={d} cpu_fallbacks={d} host_composition_components={d} pow_dispatches={d} runtime_released=true manifest_sha256={s} profile={s} framework_dispatches={d}\n", .{
        delta.counters.metalDispatchTotal(),           delta.counters.metal_poseidon2_merkle_commits,
        delta.counters.cpuFallbackTotal(),             delta.counters.cpu_composition_components,
        delta.counters.metal_proof_of_work_dispatches, std.fmt.bytesToHex(manifest, .lower),
        @tagName(selected_aot),                        delta.counters.metal_framework_polynomial_dispatches,
    });
    const json = if (batch_report) |result|
        try std.json.Stringify.valueAlloc(allocator, .{ .endpoint = "detached_parent_batch", .reports = result.reports, .plan_builds = result.plan_builds, .pcs_plan_builds = result.pcs_plan_builds, .pcs_plan_hits = result.pcs_plan_hits, .pcs_plan_retained_bytes = result.pcs_plan_retained_bytes, .requests = result.requests, .retained_scratch_bytes = result.retained_scratch_bytes, .elapsed_ns = result.elapsed_ns }, .{})
    else
        try std.json.Stringify.valueAlloc(allocator, report.?, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
