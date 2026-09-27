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
    if (std.mem.eql(u8, mode, "authenticated_aot")) {
        const bundle = try std.process.getEnvVarOwned(allocator, "STWO_RISCV_METAL_AOT_BUNDLE");
        defer allocator.free(bundle);
        var directory = try std.fs.cwd().openDir(bundle, .{});
        defer directory.close();
        const anchor = try directory.readFileAlloc(allocator, "stwo_zig_core.manifest.sha256", 256);
        defer allocator.free(anchor);
        if (anchor.len < 64) return error.InvalidManifestTrustAnchor;
        var digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&digest, anchor[0..64]);
        try Engine.initializeRuntime(allocator, .{ .authenticated_aot = .{
            .bundle_path = bundle, .manifest_sha256 = digest,
        } });
    } else if (std.mem.eql(u8, mode, "source_jit")) {
        try Engine.initializeRuntime(allocator, .source_jit);
    } else return error.InvalidRuntimeMode;
    defer Engine.Backend.shutdown() catch unreachable;
    const before = try Engine.telemetrySnapshot();
    try @import("secp256k1_proof_harness").cspProof(Engine, if (std.mem.eql(u8, mode, "source_jit")) "metal_source_jit" else "metal_authenticated_aot");
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    inline for (@typeInfo(@TypeOf(delta.counters)).@"struct".fields) |field| {
        if (comptime std.mem.startsWith(u8, field.name, "cpu_")) {
            const count = @field(delta.counters, field.name);
            if (count != 0) std.debug.print("CSP_METAL_FALLBACK {s}={d}\n", .{field.name, count});
        }
    }
    std.debug.print("CSP_METAL dispatches={d} fallbacks={d} runtime={s}\n", .{delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal(), mode});
}
