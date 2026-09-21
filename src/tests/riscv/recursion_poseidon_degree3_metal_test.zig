//! Complete universal-provider CPU/Metal parity under an admitted core AOT.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const metal = @import("stwo_metal_backend");
const wire = @import("stwo_proof_wire");
const proof = @import("poseidon2_universal_proof_v1_test.zig");
const MetalEngine = prover.engine.ProverEngine(metal.MetalCommitBackend, wire.Hasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel);

test "recursive universal degree3 Metal proof matches CPU and freshly verifies" {
    const allocator = std.testing.allocator;
    const path = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_POSEIDON_AOT_BUNDLE");
    defer allocator.free(path);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_POSEIDON_AOT_MANIFEST_SHA256");
    defer allocator.free(pin);
    var digest: [32]u8 = undefined;
    if (pin.len != 64) return error.InvalidManifestPin;
    _ = try std.fmt.hexToBytes(&digest, pin);
    try metal.MetalCommitBackend.initializeRuntime(allocator, .{ .authenticated_aot = .{ .bundle_path = path, .manifest_sha256 = digest, .profile = .core_v2 } });
    defer metal.MetalCommitBackend.shutdown() catch unreachable;
    const trace_log: u32 = 12;
    const cpu = try proof.produceWithEngineAtLog(proof.Engine, allocator, trace_log);
    defer allocator.free(cpu.bytes);
    const before = try MetalEngine.telemetrySnapshot();
    const gpu = try proof.produceWithEngineAtLog(MetalEngine, allocator, trace_log);
    defer allocator.free(gpu.bytes);
    const delta = (try MetalEngine.telemetrySnapshot()).delta(before);
    try std.testing.expectEqualSlices(u8, cpu.bytes, gpu.bytes);
    try std.testing.expectEqualDeep(cpu.claims, gpu.claims);
    try std.testing.expect(delta.counters.metal_circle_transform_dispatches > 0);
    try proof.verifyAtLog(allocator, gpu, trace_log);
    var changed = gpu;
    changed.claims[1] = changed.claims[1].add(core.fields.qm31.QM31.one());
    if (proof.verifyAtLog(allocator, changed, trace_log)) |_| return error.ExpectedClaimRejection else |_| {}
    std.debug.print("RECURSIVE_POSEIDON_DEGREE3_METAL bytes={} same_cpu_bytes=true producer_destroyed=true fresh_cpu_verified=true transform_dispatches={} composition_runs_on_host=true\n", .{ gpu.bytes.len, delta.counters.metal_circle_transform_dispatches });
}
