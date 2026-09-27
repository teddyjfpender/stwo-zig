//! Shared canonical CSP check with explicit JIT or authenticated AOT selection.
const std = @import("std");
const metal = @import("stwo_metal_backend");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Engine = @import("stwo_prover_engine").engine.ProverEngine(metal.MetalCommitBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
test "Metal BLAKE3 canonical CSP ECDSA proves and independently verifies" {
    const allocator = std.heap.smp_allocator;
    const mode = try std.process.getEnvVarOwned(allocator, "STWO_BLAKE3_CSP_RUNTIME");
    defer allocator.free(mode);
    try @import("blake3_runtime").initialize(Engine, allocator, mode);
    defer Engine.Backend.shutdown() catch unreachable;
    const before = try Engine.telemetrySnapshot();
    try @import("secp256k1_proof_harness").cspProof(Engine, if (std.mem.eql(u8, mode, "source_jit")) "metal_source_jit" else "metal_authenticated_aot");
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    inline for (@typeInfo(@TypeOf(delta.counters)).@"struct".fields) |field| {
        if (comptime std.mem.startsWith(u8, field.name, "cpu_")) {
            const count = @field(delta.counters, field.name);
            if (count != 0) std.debug.print("CSP_METAL_CPU_WORK {s}={d}\n", .{ field.name, count });
        }
    }
    std.debug.print("CSP_METAL dispatches={d} fallbacks={d} runtime={s}\n", .{ delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal(), mode });
}
