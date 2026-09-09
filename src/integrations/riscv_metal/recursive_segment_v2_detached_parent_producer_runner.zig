//! Metal runtime boundary for the shared detached recursive parent transaction.
//! The independent CPU verifier consumes the same admitted key and proof ABI.
const std = @import("std");
const metal = @import("stwo_metal_backend");
const Backend = metal.MetalCommitBackend;
const Engine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(Backend);
const producer = @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_parent_producer;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 5 or !std.mem.eql(u8, args[1], "--aot-bundle") or
        !std.mem.eql(u8, args[3], "--aot-manifest-sha256") or args[4].len != 64)
        return error.ExpectedAotBundleAndManifestSha256;
    const input = try producer.parseArguments(args[5..]);
    try Backend.admitHostProving(.recursive_preparation);
    var manifest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&manifest, args[4]);
    try @import("aot_bundle_admission.zig").validate(allocator, args[2], manifest);
    if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeAlreadyInitialized;
    try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{
        .bundle_path = args[2],
        .manifest_sha256 = manifest,
        .profile = .core_v2,
    } });
    defer if (Backend.runtimeLifecycleSnapshot().initialized) {
        Backend.shutdown() catch unreachable;
    };
    const before = try Backend.telemetrySnapshot();
    const lifecycle = Backend.runtimeLifecycleSnapshot();
    const identity = lifecycle.identity orelse return error.AuthenticatedMetalRuntimeMissing;
    if (identity.origin != .authenticated_core_aot or identity.manifest_sha256 == null or
        !std.meta.eql(identity.manifest_sha256.?, manifest) or
        !std.meta.eql(identity.source_sha256, metal.shaders.aot_profile.Profile.core_v2.sourceDigest()))
        return error.AuthenticatedMetalRuntimeMismatch;
    const report = try producer.runWithEngine(Engine, allocator, input);
    const after = Backend.runtimeLifecycleSnapshot();
    if (!std.meta.eql(after.identity, lifecycle.identity) or after.active_call_leases != 0 or
        after.initialization_count != lifecycle.initialization_count or after.shutdown_count != lifecycle.shutdown_count)
        return error.MetalRuntimeChanged;
    const delta = (try Backend.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    if (delta.counters.metal_poseidon2_merkle_commits == 0) return error.MetalPoseidonDispatchMissing;
    try Backend.shutdown();
    if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeNotReleased;
    std.debug.print("DETACHED_PARENT_METAL dispatches={d} poseidon_commits={d} cpu_fallbacks={d} host_composition_components={d} pow_dispatches={d} runtime_released=true manifest_sha256={s}\n", .{
        delta.counters.metalDispatchTotal(),           delta.counters.metal_poseidon2_merkle_commits,
        delta.counters.cpuFallbackTotal(),             delta.counters.cpu_composition_components,
        delta.counters.metal_proof_of_work_dispatches, std.fmt.bytesToHex(manifest, .lower),
    });
    const json = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
