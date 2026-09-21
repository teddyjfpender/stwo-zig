//! Explicit AOT GPU gate for the new Ethereum provider; no default activation.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const metal = @import("stwo_metal_backend");
const wire = @import("stwo_proof_wire");
const proof = @import("poseidon2_narrow_proof_v1_test.zig");
const export_program = @import("stwo_riscv_frontend").testing.component_proof.narrow_backend;
const MetalEngine = prover.engine.ProverEngine(metal.MetalCommitBackend, wire.Hasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel);

test "Ethereum narrow Metal authenticated AOT complete proof matches CPU bytes" {
    const allocator = std.testing.allocator;
    const path = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_NARROW_AOT_BUNDLE");
    defer allocator.free(path);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_NARROW_AOT_MANIFEST_SHA256");
    defer allocator.free(pin);
    var digest: [32]u8 = undefined;
    if (pin.len != 64) return error.InvalidManifestPin;
    _ = try std.fmt.hexToBytes(&digest, pin);
    try metal.MetalCommitBackend.initializeRuntime(allocator, .{ .authenticated_aot = .{ .bundle_path = path, .manifest_sha256 = digest, .profile = .ethereum_fixed_program_narrow_v1 } });
    defer metal.MetalCommitBackend.shutdown() catch unreachable;
    {
        var lease = try metal.shared_runtime.acquire();
        defer lease.deinit();
        // Resolve every new AOT pipeline before committing even this tiny proof.
        for (0..export_program.DIRECT_PARTITION_COUNT) |partition| {
            var program = try export_program.buildDirect(allocator, partition);
            defer program.deinit();
            const name = try metal.riscv_polynomial_codegen.base.kernelName(allocator, program);
            defer allocator.free(name);
            var plan = try lease.runtime.prepareBasePolynomialAot(name);
            plan.deinit();
        }
        var program = try export_program.buildLookup(allocator);
        defer program.deinit();
        const name = try metal.riscv_polynomial_codegen.lookup.kernelName(allocator, program);
        defer allocator.free(name);
        var plan = try lease.runtime.prepareLookupPolynomialAot(name);
        plan.deinit();
    }
    // Match the existing measured GPU mixed-component crossover (qlog16).
    const trace_log: u32 = 15;
    const cpu = try proof.produceWithEngineAtLog(proof.Engine, allocator, trace_log);
    defer allocator.free(cpu.bytes);
    const before = try MetalEngine.telemetrySnapshot();
    const gpu = try proof.produceWithEngineAtLog(MetalEngine, allocator, trace_log);
    defer allocator.free(gpu.bytes);
    const after = try MetalEngine.telemetrySnapshot();
    const delta = after.delta(before);
    std.debug.print("NARROW_GPU_COUNTERS base={} lookup={} eligible_base={} eligible_lookup={} same_bytes={}\n", .{ delta.counters.metal_riscv_base_polynomial_batch_dispatches, delta.counters.metal_riscv_lookup_polynomial_batch_dispatches, delta.counters.riscv_base_polynomial_eligible_components, delta.counters.riscv_lookup_polynomial_eligible_components, std.mem.eql(u8, cpu.bytes, gpu.bytes) });
    try std.testing.expect(delta.counters.metal_riscv_base_polynomial_batch_dispatches > 0);
    try std.testing.expect(delta.counters.metal_riscv_lookup_polynomial_batch_dispatches > 0);
    try std.testing.expectEqualSlices(u8, cpu.bytes, gpu.bytes);
    try std.testing.expectEqualDeep(cpu.claims, gpu.claims);
    try proof.verifyAtLog(allocator, gpu, trace_log);
    std.debug.print("ETHEREUM_NARROW_METAL_PROOF bytes={} same_cpu_bytes=true producer_destroyed=true fresh_cpu_verified=true base_dispatches={} lookup_dispatches={}\n", .{ gpu.bytes.len, delta.counters.metal_riscv_base_polynomial_batch_dispatches, delta.counters.metal_riscv_lookup_polynomial_batch_dispatches });
}
